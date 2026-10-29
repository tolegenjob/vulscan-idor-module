package io.vulscan.idor.auth

import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.SessionCheck
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.kit.worker.BudgetedHttp
import io.vulscan.idor.identity.IdentityContext
import io.vulscan.idor.identity.SessionState
import io.vulscan.idor.json.JsonPath
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** Исход запроса, выполненного с учётом состояния сессии. */
sealed interface SessionResult {
    data class Ok(val response: ProbeResponse) : SessionResult
    data object Expired : SessionResult
}

/** Результат одного вызова sessionCheck: статус-код и, если задан identityMarker, его значение. */
class SessionCheckOutcome(val response: ProbeResponse, val statusMatched: Boolean, val marker: String?)

/**
 * Устанавливает и поддерживает сессии идентичностей. Повторный вход допускается не более
 * [maxReLoginAttempts] раз на идентичность за задание (I-2, этап "Истечение сессии").
 */
class SessionManager(
    private val authenticatorFor: (AuthType) -> Authenticator = ::defaultAuthenticator,
    private val maxReLoginAttempts: Int = 2,
) {
    private val reLoginCounts = ConcurrentHashMap<UUID, Int>()

    /** Логин по `authType` идентичности; для статических типов — заглушка (заголовок уже установлен). */
    fun establish(identity: IdentityContext, http: BudgetedHttp): AuthOutcome {
        val outcome = authenticatorFor(identity.authType).authenticate(identity, http)
        identity.sessionState = if (outcome is AuthOutcome.Success) SessionState.ACTIVE else SessionState.AUTH_FAILED
        return outcome
    }

    /** Один запрос к `check.endpointId` от имени identity: статус и значение `identityMarker`, если он задан. */
    fun readSessionCheck(identity: IdentityContext, http: BudgetedHttp, endpoint: EndpointRef, check: SessionCheck): SessionCheckOutcome {
        val response = identity.execute(http, ProbeRequest(HttpMethod.GET, endpoint.url))
        val marker = check.identityMarker?.let { JsonPath.readString(response.bodyText(), it) }
        return SessionCheckOutcome(response, response.status == check.expectStatus, marker)
    }

    /** Сравнивает `identityMarker` с label идентичности; провал (не нашёлся или не совпал) помечает identity как EXPIRED. */
    fun verify(identity: IdentityContext, http: BudgetedHttp, endpoint: EndpointRef, check: SessionCheck): AuthOutcome {
        val outcome = readSessionCheck(identity, http, endpoint, check)
        val result = when {
            !outcome.statusMatched -> AuthOutcome.Failed("sessionCheck expected status ${check.expectStatus}, got ${outcome.response.status}")
            check.identityMarker == null -> AuthOutcome.Success
            outcome.marker == null -> AuthOutcome.Failed("identityMarker not found in sessionCheck response")
            outcome.marker != identity.label -> AuthOutcome.Failed("identityMarker mismatch: expected ${identity.label}, got ${outcome.marker}")
            else -> AuthOutcome.Success
        }
        if (result is AuthOutcome.Failed) identity.sessionState = SessionState.EXPIRED
        return result
    }

    /** Две идентичности, у которых sessionCheck вернул один и тот же маркер — на самом деле один и тот же пользователь. */
    fun findIdentityCollision(markers: Map<UUID, String>): Pair<UUID, UUID>? {
        val byValue = mutableMapOf<String, UUID>()
        for ((id, value) in markers) {
            val other = byValue.putIfAbsent(value, id)
            if (other != null) return other to id
        }
        return null
    }

    private fun looksExpired(response: ProbeResponse, identity: IdentityContext): Boolean {
        val loginUrl = identity.configValue("loginUrl")
        val redirectsToLogin = response.status in 300..399 &&
            loginUrl != null && response.headers.entries.firstOrNull { it.key.equals("location", true) }?.value?.contains(loginUrl) == true
        return response.status == 401 || redirectsToLogin
    }

    /**
     * Выполняет запрос от имени identity; если сессия похожа на истёкшую — один повторный вход и повтор
     * запроса, не более [maxReLoginAttempts] раз за всё задание. После исчерпания — [SessionResult.Expired].
     */
    fun execute(identity: IdentityContext, http: BudgetedHttp, request: ProbeRequest): SessionResult {
        val response = identity.execute(http, request)
        if (!looksExpired(response, identity)) return SessionResult.Ok(response)

        val attempts = reLoginCounts.getOrDefault(identity.identityId, 0)
        if (attempts >= maxReLoginAttempts) {
            identity.sessionState = SessionState.EXPIRED
            return SessionResult.Expired
        }
        reLoginCounts[identity.identityId] = attempts + 1
        val relogin = establish(identity, http)
        if (relogin !is AuthOutcome.Success) {
            identity.sessionState = SessionState.EXPIRED
            return SessionResult.Expired
        }
        val retried = identity.execute(http, request)
        if (looksExpired(retried, identity)) {
            identity.sessionState = SessionState.EXPIRED
            return SessionResult.Expired
        }
        return SessionResult.Ok(retried)
    }

    companion object {
        fun defaultAuthenticator(type: AuthType): Authenticator = when (type) {
            AuthType.FORM_LOGIN -> FormLoginAuthenticator
            AuthType.JSON_LOGIN -> JsonLoginAuthenticator
            AuthType.BEARER_STATIC, AuthType.COOKIE_STATIC, AuthType.HEADER_STATIC -> StaticCredentialAuthenticator
        }
    }
}
