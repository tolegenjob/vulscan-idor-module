package io.vulscan.idor.auth

import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.worker.BudgetedHttp
import io.vulscan.idor.identity.IdentityContext
import io.vulscan.idor.json.JsonPath

/** `JSON_LOGIN`: POST JSON с полями входа, токен достаётся по `tokenJsonPath` и идёт в `Authorization: Bearer`. */
object JsonLoginAuthenticator : Authenticator {
    override fun authenticate(identity: IdentityContext, http: BudgetedHttp): AuthOutcome {
        val loginUrl = identity.configValue("loginUrl") ?: return AuthOutcome.Failed("loginUrl is not configured")
        val usernameField = identity.configValue("usernameField") ?: "username"
        val passwordField = identity.configValue("passwordField") ?: "password"
        val tokenPath = identity.configValue("tokenJsonPath") ?: return AuthOutcome.Failed("tokenJsonPath is not configured")
        val username = identity.secret("username") ?: return AuthOutcome.Failed("username secret is missing")
        val password = identity.secret("password") ?: return AuthOutcome.Failed("password secret is missing")

        val payload = "{\"$usernameField\":${quote(username)},\"$passwordField\":${quote(password)}}"
        val response = identity.execute(http, ProbeRequest(HttpMethod.POST, loginUrl, body = payload.toByteArray(Charsets.UTF_8), contentType = "application/json"))
        if (response.status !in 200..299) return AuthOutcome.Failed("login request returned status ${response.status}")

        val token = JsonPath.readString(response.bodyText(), tokenPath) ?: return AuthOutcome.Failed("token field is missing in the login response")
        identity.bearerToken = token
        return AuthOutcome.Success
    }

    private fun quote(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}
