package io.vulscan.idor.identity

import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.IdentityCredential
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.kit.worker.BudgetedHttp
import java.util.UUID

/** Секретное значение в памяти, пригодное для явного обнуления после использования. */
class SecretValue(value: String) {
    private var chars: CharArray? = value.toCharArray()

    fun get(): String = chars?.let { String(it) } ?: ""

    fun clear() {
        chars?.fill('\u0000')
        chars = null
    }

    override fun toString(): String = "SecretValue([REDACTED])"
}

/**
 * Простое хранилище cookie для одной идентичности: читает `Set-Cookie` из ответа, отдаёт `Cookie` для следующего запроса.
 * Независимо от OkHttp — `ctx.http` общий для всех identity, поэтому изоляция сессий держится на уровне заголовков.
 */
class CookieStore {
    private val jar = LinkedHashMap<String, String>()

    /** Set-Cookie может быть несколько; kit объединяет их через ", ", что ломает дату в Expires — разделяем аккуратно. */
    private val SPLIT = Regex(""",(?=\s*[A-Za-z0-9_!#$%&'*+.^`|~-]+=)""")

    fun update(headers: Map<String, String>) {
        val raw = headers.entries.firstOrNull { it.key.equals("set-cookie", ignoreCase = true) }?.value ?: return
        SPLIT.split(raw).forEach { cookie ->
            val pair = cookie.trim().substringBefore(';')
            val name = pair.substringBefore('=', "").trim()
            val value = pair.substringAfter('=', "").trim()
            if (name.isNotEmpty()) jar[name] = value
        }
    }

    fun header(): String? = jar.entries.takeIf { it.isNotEmpty() }?.joinToString("; ") { (k, v) -> "$k=$v" }

    fun clear() = jar.clear()
}

/**
 * Состояние одной тестовой идентичности на время задания: свой cookie jar и заголовки аутентификации,
 * общий [BudgetedHttp] (общий бюджет запросов и ограничение скорости — исключает только смешивание сессий).
 */
class IdentityContext(
    val identityId: UUID,
    val label: String,
    val role: String,
    private val authType: AuthType,
    private val config: Map<String, String>,
    private val secrets: Map<String, SecretValue>,
) {
    private val cookies = CookieStore()

    /** Токен/cookie, полученные через логин (`FORM_LOGIN`/`JSON_LOGIN`); заполняются в I-2 (`SessionManager`). */
    @Volatile var bearerToken: String? = null
    @Volatile var sessionState: SessionState = SessionState.NOT_AUTHENTICATED

    init {
        when (authType) {
            AuthType.COOKIE_STATIC -> secrets["cookie"]?.let { cookies.update(mapOf("set-cookie" to it.get())) }
            AuthType.BEARER_STATIC -> secrets["token"]?.let { bearerToken = it.get() }
            else -> Unit
        }
    }

    private fun headers(): Map<String, String> = buildMap {
        cookies.header()?.let { put("Cookie", it) }
        bearerToken?.let { put("Authorization", "Bearer $it") }
        if (authType == AuthType.HEADER_STATIC) {
            val name = config["headerName"]
            val value = secrets["headerValue"]?.get()
            if (name != null && value != null) put(name, value)
        }
    }

    /** Отправляет запрос от имени этой идентичности: добавляет её заголовки/cookie и обновляет cookie jar из ответа. */
    fun execute(http: BudgetedHttp, request: ProbeRequest): ProbeResponse {
        val merged = ProbeRequest(request.method, request.url, headers() + request.headers, request.body, request.contentType)
        val response = http.execute(merged)
        cookies.update(response.headers)
        return response
    }

    fun configValue(key: String): String? = config[key]

    fun secret(key: String): String? = secrets[key]?.get()

    fun clear() {
        secrets.values.forEach { it.clear() }
        cookies.clear()
        bearerToken = null
    }

    override fun toString(): String = "IdentityContext(identityId=$identityId, label=$label, role=$role, authType=$authType)"

    companion object {
        fun from(credential: IdentityCredential): IdentityContext = IdentityContext(
            identityId = credential.identityId,
            label = credential.label,
            role = credential.role,
            authType = credential.auth.type,
            config = credential.auth.config,
            secrets = credential.auth.secret.mapValues { (_, v) -> SecretValue(v) },
        )
    }
}

enum class SessionState { NOT_AUTHENTICATED, ACTIVE, EXPIRED, AUTH_FAILED }
