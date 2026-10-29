package io.vulscan.idor.auth

import io.vulscan.kit.contracts.AuthSpec
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.IdentityCredential
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.idor.TestJobs
import io.vulscan.idor.TestJobs.identity
import io.vulscan.idor.TestRun
import io.vulscan.idor.identity.IdentityContext
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URLDecoder

class FormLoginAuthenticatorTest {
    private fun context(password: String = "correct", config: Map<String, String> = mapOf("loginUrl" to "${TestJobs.BASE}/login")) =
        IdentityContext.from(
            IdentityCredential(identity("alice").identityId, "alice", "USER", AuthSpec(AuthType.FORM_LOGIN, config, mapOf("username" to "alice", "password" to password))),
        )

    private fun post(body: String): Map<String, String> =
        body.split("&").associate { val (k, v) = it.split("="); URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8) }

    @Test
    fun `correct credentials succeed`() {
        val identity = context()
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { request ->
            val fields = post(String(request.body!!, Charsets.UTF_8))
            val ok = fields["username"] == "alice" && fields["password"] == "correct"
            TestJobs.response(if (ok) "{}" else "{}", status = if (ok) 200 else 401, headers = if (ok) mapOf("Set-Cookie" to "session=tok") else emptyMap())
        }
        val outcome = FormLoginAuthenticator.authenticate(identity, run.http)
        assertThat(outcome).isEqualTo(AuthOutcome.Success)
        assertThat(run.requests.single().method).isEqualTo(HttpMethod.POST)
        assertThat(run.requests.single().url).isEqualTo("${TestJobs.BASE}/login")
    }

    @Test
    fun `wrong password fails`() {
        val identity = context(password = "wrong")
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { request ->
            val fields = post(String(request.body!!, Charsets.UTF_8))
            TestJobs.response("login failed", status = if (fields["password"] == "correct") 200 else 401)
        }
        val outcome = FormLoginAuthenticator.authenticate(identity, run.http)
        assertThat(outcome).isInstanceOf(AuthOutcome.Failed::class.java)
    }

    @Test
    fun `csrf token from the login page is submitted with the form`() {
        val config = mapOf(
            "loginUrl" to "${TestJobs.BASE}/login",
            "csrfFieldRegex" to """name="csrf" value="([a-f0-9]+)"""",
            "csrfFieldName" to "csrf",
        )
        val identity = IdentityContext.from(
            IdentityCredential(identity("alice").identityId, "alice", "USER", AuthSpec(AuthType.FORM_LOGIN, config, mapOf("username" to "alice", "password" to "correct"))),
        )
        var sentCsrf: String? = null
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { request ->
            if (request.method == HttpMethod.GET) {
                TestJobs.response("""<form><input type="hidden" name="csrf" value="abc123def"></form>""")
            } else {
                sentCsrf = post(String(request.body!!, Charsets.UTF_8))["csrf"]
                TestJobs.response("ok")
            }
        }
        val outcome = FormLoginAuthenticator.authenticate(identity, run.http)
        assertThat(outcome).isEqualTo(AuthOutcome.Success)
        assertThat(sentCsrf).isEqualTo("abc123def")
        assertThat(run.requests).hasSize(2)
    }

    @Test
    fun `missing loginUrl fails without any request`() {
        val identity = context(config = emptyMap())
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { TestJobs.response("ok") }
        assertThat(FormLoginAuthenticator.authenticate(identity, run.http)).isInstanceOf(AuthOutcome.Failed::class.java)
        assertThat(run.requests).isEmpty()
    }
}
