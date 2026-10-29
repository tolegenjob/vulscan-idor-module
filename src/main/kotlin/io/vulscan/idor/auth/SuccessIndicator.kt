package io.vulscan.idor.auth

import io.vulscan.kit.net.ProbeResponse
import io.vulscan.idor.identity.IdentityContext

/**
 * `successIndicator` из конфигурации идентичности: `redirect:<path>` — 3xx на этот путь;
 * `cookie:<name>` — такой cookie получен; иначе — подстрока тела ответа. Пустой/нет конфигурации → по статусу 2xx/3xx.
 */
object SuccessIndicator {
    fun matches(indicator: String?, response: ProbeResponse, identity: IdentityContext): Boolean = when {
        indicator == null -> response.status in 200..399
        indicator.startsWith("redirect:") -> {
            val path = indicator.removePrefix("redirect:")
            response.status in 300..399 && response.headers.entries.firstOrNull { it.key.equals("location", true) }?.value?.contains(path) == true
        }
        indicator.startsWith("cookie:") -> identity.hasCookie(indicator.removePrefix("cookie:"))
        else -> response.bodyText().contains(indicator)
    }
}
