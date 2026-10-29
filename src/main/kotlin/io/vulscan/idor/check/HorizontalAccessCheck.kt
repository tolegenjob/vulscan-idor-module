package io.vulscan.idor.check

import io.vulscan.idor.auth.SessionManager
import io.vulscan.idor.auth.SessionResult
import io.vulscan.idor.compare.ResponseSignature
import io.vulscan.idor.identity.IdentityContext
import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.ExpectedAccess
import io.vulscan.kit.contracts.ResourceRef
import io.vulscan.kit.worker.BudgetedHttp
import java.util.UUID

/** Итог проверки одного правила доступа (`resource` × `rule.identityId`) по I-3. */
data class HorizontalCheckResult(
    val resourceId: UUID,
    val attackerId: UUID,
    val outcome: AccessOutcome,
    val markerMatch: MarkerMatchResult? = null,
    val repeatConfirmed: Boolean = false,
    val anonymousStatus: Int? = null,
    /** Заполнено, если проверка не дошла до классификации (сессия/baseline подвели), а не из-за самого доступа. */
    val inconclusiveReason: String? = null,
)

/**
 * Горизонтальная проверка доступа: для одного ресурса и одной пары (владелец, другая identity) выясняет,
 * действительно ли «другая identity» видит данные владельца там, где должна получить отказ (I-3 ТЗ).
 */
class HorizontalAccessCheck(
    private val http: BudgetedHttp,
    private val sessions: SessionManager,
    private val denialSimilarityThreshold: Double = 0.90,
) {
    fun check(
        endpoint: EndpointRef,
        resource: ResourceRef,
        rule: AccessRuleRef,
        owner: IdentityContext,
        other: IdentityContext?,
    ): HorizontalCheckResult {
        val resourceRequest = ResourceRequestFactory.build(endpoint, resource.idParameter, resource.idValue)

        // 1. Базовая линия владельца: 2xx и (если маркеры заданы) все найдены в его собственном ответе.
        val ownerResult = sessions.execute(owner, http, resourceRequest)
        if (ownerResult !is SessionResult.Ok) {
            return inconclusive(resource, rule, "OWNER_SESSION_EXPIRED")
        }
        val ownerResponse = ownerResult.response
        val ownerBody = ownerResponse.bodyText()
        val ownerMarkersOk = resource.ownerMarkers.isEmpty() ||
            OwnerMarkerMatcher.match(resource.ownerMarkers, ownerBody, ownerBody).all
        if (ownerResponse.status !in 200..299 || !ownerMarkersOk) {
            return inconclusive(resource, rule, "OWNER_BASELINE_FAILED")
        }
        val ownerSignature = ResponseSignature.of(ownerResponse)

        // 2. Анонимный контроль: ресурс может быть публичным независимо от того, что проверяется.
        val anonymousResponse = http.execute(ResourceRequestFactory.anonymous(endpoint, resource.idParameter, resource.idValue))
        val anonymousMatch = OwnerMarkerMatcher.match(resource.ownerMarkers, ownerBody, anonymousResponse.bodyText())
        if (anonymousResponse.status in 200..299 && anonymousMatch.any) {
            return HorizontalCheckResult(resource.resourceId, rule.identityId, AccessOutcome.PUBLIC_OBSERVED, anonymousMatch, anonymousStatus = anonymousResponse.status)
        }

        when (rule.expected) {
            ExpectedAccess.PUBLIC ->
                return HorizontalCheckResult(resource.resourceId, rule.identityId, AccessOutcome.AMBIGUOUS, anonymousMatch, anonymousStatus = anonymousResponse.status)

            ExpectedAccess.ALLOW -> {
                val identity = other ?: return inconclusive(resource, rule, "UNKNOWN_IDENTITY")
                val allowed = sessions.execute(identity, http, resourceRequest)
                if (allowed !is SessionResult.Ok) return inconclusive(resource, rule, "SESSION_EXPIRED")
                val match = OwnerMarkerMatcher.match(resource.ownerMarkers, ownerBody, allowed.response.bodyText())
                // Несовпадение здесь — расхождение конфигурации, а не IDOR: finding не формируется (см. I-5).
                val outcome = if (allowed.response.status in 200..299) AccessOutcome.ALLOWED_AS_EXPECTED else AccessOutcome.AMBIGUOUS
                return HorizontalCheckResult(resource.resourceId, rule.identityId, outcome, match, anonymousStatus = anonymousResponse.status)
            }

            ExpectedAccess.DENY -> {
                val attacker = other ?: return inconclusive(resource, rule, "UNKNOWN_IDENTITY")
                return checkDenial(endpoint, resource, rule, attacker, ownerBody, ownerSignature, anonymousResponse.status)
            }
        }
    }

    private fun checkDenial(
        endpoint: EndpointRef,
        resource: ResourceRef,
        rule: AccessRuleRef,
        attacker: IdentityContext,
        ownerBody: String,
        ownerSignature: ResponseSignature,
        anonymousStatus: Int,
    ): HorizontalCheckResult {
        val resourceRequest = ResourceRequestFactory.build(endpoint, resource.idParameter, resource.idValue)
        val loginUrl = attacker.configValue("loginUrl")

        // 3. «Форма отказа»: запрос гарантированно несуществующего id от имени атакующего.
        val canary = UUID.randomUUID().toString().take(8)
        val nonexistent = ResourceRequestFactory.nonexistentValue(resource.idValue, canary)
        val denialRequest = ResourceRequestFactory.build(endpoint, resource.idParameter, nonexistent)
        val denialResult = sessions.execute(attacker, http, denialRequest)
        if (denialResult !is SessionResult.Ok) return inconclusive(resource, rule, "SESSION_EXPIRED")
        val denialShape = DenialShape.of(denialResult.response)

        fun probeOnce(): Pair<SessionResult.Ok, MarkerMatchResult>? {
            val result = sessions.execute(attacker, http, resourceRequest)
            if (result !is SessionResult.Ok) return null
            return result to OwnerMarkerMatcher.match(resource.ownerMarkers, ownerBody, result.response.bodyText())
        }

        // 4. Проба.
        val (firstResult, firstMatch) = probeOnce() ?: return inconclusive(resource, rule, "SESSION_EXPIRED")
        var outcome = ResponseClassifier.classify(firstResult.response, ownerSignature, denialShape.signature, firstMatch, loginUrl, denialSimilarityThreshold)

        // 5. UNAUTHORIZED_ACCESS подтверждается повторным запросом; иначе — AMBIGUOUS.
        var repeatConfirmed = false
        if (outcome == AccessOutcome.UNAUTHORIZED_ACCESS) {
            val second = probeOnce()
            if (second == null) return inconclusive(resource, rule, "SESSION_EXPIRED")
            val (secondResult, secondMatch) = second
            val secondOutcome = ResponseClassifier.classify(secondResult.response, ownerSignature, denialShape.signature, secondMatch, loginUrl, denialSimilarityThreshold)
            if (secondOutcome == AccessOutcome.UNAUTHORIZED_ACCESS) repeatConfirmed = true else outcome = AccessOutcome.AMBIGUOUS
        }

        return HorizontalCheckResult(resource.resourceId, rule.identityId, outcome, firstMatch, repeatConfirmed, anonymousStatus)
    }

    private fun inconclusive(resource: ResourceRef, rule: AccessRuleRef, reason: String) =
        HorizontalCheckResult(resource.resourceId, rule.identityId, AccessOutcome.ERROR, inconclusiveReason = reason)
}
