package io.vulscan.idor.report

import io.vulscan.idor.check.AccessOutcome
import io.vulscan.idor.check.HorizontalCheckResult
import io.vulscan.idor.check.MarkerMatchResult
import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.FindingPayload
import io.vulscan.kit.contracts.Fingerprint
import io.vulscan.kit.contracts.IdorDetails
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.ResourceRef
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType

private const val RECOMMENDATION =
    "Проверяйте авторизацию на сервере при каждом обращении к объекту (по владельцу или роли), " +
        "а не только аутентификацию. Непрозрачные идентификаторы (UUID вместо порядкового номера) — " +
        "дополнительная мера, а не замена проверки доступа. Используйте централизованный authorization-слой " +
        "и добавьте негативные тесты на межпользовательский доступ к тем же эндпоинтам."

/**
 * Собирает [FindingPayload] из результата [io.vulscan.idor.check.HorizontalAccessCheck] /
 * [io.vulscan.idor.check.VerticalAccessCheck] (I-5 ТЗ). Возвращает `null`, если проверка не доказала
 * ничего, что стоило бы публиковать как finding (DENIED/ERROR/AMBIGUOUS и т.п.) — только
 * `UNAUTHORIZED_ACCESS` (CONFIRMED/LIKELY) и `AMBIGUOUS_STRUCTURE` (SUSPECTED) становятся findings.
 */
object IdorFindingFactory {
    fun create(
        endpoint: EndpointRef,
        resource: ResourceRef,
        vulnType: VulnType,
        result: HorizontalCheckResult,
        ownerLabel: String,
        attackerLabel: String,
        ownerSessionOk: Boolean,
        attackerSessionOk: Boolean,
        assumption: String? = null,
    ): FindingPayload? {
        if (result.outcome != AccessOutcome.UNAUTHORIZED_ACCESS && result.outcome != AccessOutcome.AMBIGUOUS_STRUCTURE) return null

        val markerMatch = result.markerMatch ?: MarkerMatchResult(emptyList(), 0)
        val verdict = verdictOf(result, markerMatch, ownerSessionOk, attackerSessionOk)
        val severity = IdorSeverityPolicy.severity(resource.sensitivity, vulnType, verdict)
        val confidenceBase = IdorConfidenceScorer.score(verdict, markerMatch.ratio, denialShapeAvailable = true)
        val confidence = if (assumption != null) (confidenceBase - 10).coerceIn(1, 99) else confidenceBase

        val fingerprint = Fingerprint.of(
            "IDOR", vulnType.name, endpoint.method.name, endpoint.url,
            resource.idParameter.name, resource.ownerIdentityId.toString(), result.attackerId.toString(),
        )

        val title = if (vulnType == VulnType.IDOR_VERTICAL) {
            "Повышение привилегий из-за отсутствия проверки роли (IDOR)"
        } else {
            "Небезопасная прямая ссылка на объект (IDOR)"
        }
        val summary = "Идентичность «$attackerLabel» получила доступ к данным «$ownerLabel» " +
            "через ${endpoint.method} ${endpoint.url}, хотя по матрице доступа этого не должно быть."

        return FindingPayload(
            moduleType = ModuleType.IDOR,
            vulnType = vulnType,
            cwe = "CWE-639",
            endpointId = endpoint.endpointId,
            method = endpoint.method,
            url = endpoint.url,
            parameter = resource.idParameter,
            verdict = verdict,
            severity = severity,
            confidence = confidence,
            fingerprint = fingerprint,
            title = title,
            summary = summary,
            recommendation = RECOMMENDATION,
            details = IdorDetails(
                type = vulnType,
                ownerLabel = ownerLabel,
                attackerLabel = attackerLabel,
                markersMatched = markerMatch.matched.map { it.path },
                markersTotal = markerMatch.total,
                repeatConfirmed = result.repeatConfirmed,
                anonymousStatus = result.anonymousStatus,
                assumption = assumption,
            ),
            evidence = IdorEvidenceBuilder.build(result),
        )
    }

    private fun verdictOf(
        result: HorizontalCheckResult,
        markerMatch: MarkerMatchResult,
        ownerSessionOk: Boolean,
        attackerSessionOk: Boolean,
    ): Verdict = when {
        result.outcome == AccessOutcome.AMBIGUOUS_STRUCTURE || markerMatch.total == 0 -> Verdict.SUSPECTED
        markerMatch.all && result.repeatConfirmed && ownerSessionOk && attackerSessionOk -> Verdict.CONFIRMED
        else -> Verdict.LIKELY
    }
}
