package io.vulscan.idor.auth

import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.worker.BudgetedHttp
import io.vulscan.idor.identity.IdentityContext
import java.net.URLEncoder

/**
 * `FORM_LOGIN`: GET страницы логина (чтобы при необходимости извлечь CSRF-токен формы),
 * POST полей `usernameField`/`passwordField` (+ токен), проверка признака успеха.
 */
object FormLoginAuthenticator : Authenticator {
    override fun authenticate(identity: IdentityContext, http: BudgetedHttp): AuthOutcome {
        val loginUrl = identity.configValue("loginUrl") ?: return AuthOutcome.Failed("loginUrl is not configured")
        val usernameField = identity.configValue("usernameField") ?: "username"
        val passwordField = identity.configValue("passwordField") ?: "password"
        val username = identity.secret("username") ?: return AuthOutcome.Failed("username secret is missing")
        val password = identity.secret("password") ?: return AuthOutcome.Failed("password secret is missing")

        val fields = LinkedHashMap<String, String>()
        identity.configValue("csrfFieldRegex")?.let { regex ->
            val page = identity.execute(http, ProbeRequest(HttpMethod.GET, loginUrl))
            val match = Regex(regex).find(page.bodyText()) ?: return AuthOutcome.Failed("csrf token not found on the login page")
            val csrfField = identity.configValue("csrfFieldName") ?: "csrf_token"
            fields[csrfField] = match.groupValues.getOrElse(1) { match.value }
        }
        fields[usernameField] = username
        fields[passwordField] = password

        val body = fields.entries.joinToString("&") { (k, v) -> "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}" }
        val response = identity.execute(http, ProbeRequest(HttpMethod.POST, loginUrl, body = body.toByteArray(Charsets.UTF_8), contentType = "application/x-www-form-urlencoded"))

        return if (SuccessIndicator.matches(identity.configValue("successIndicator"), response, identity)) {
            AuthOutcome.Success
        } else {
            AuthOutcome.Failed("login did not match the configured success indicator")
        }
    }
}
