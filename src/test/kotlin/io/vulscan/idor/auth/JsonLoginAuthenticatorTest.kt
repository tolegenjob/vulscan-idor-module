package io.vulscan.idor.auth

import io.vulscan.kit.contracts.AuthSpec
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.IdentityCredential
import io.vulscan.idor.TestJobs
import io.vulscan.idor.TestJobs.identity
import io.vulscan.idor.TestRun
import io.vulscan.idor.identity.IdentityContext
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JsonLoginAuthenticatorTest {
    private fun context(config: Map<String, String> = mapOf("loginUrl" to "${TestJobs.BASE}/login", "tokenJsonPath" to "$.token")) =
        IdentityContext.from(
            IdentityCredential(identity("alice").identityId, "alice", "USER", AuthSpec(AuthType.JSON_LOGIN, config, mapOf("username" to "alice", "password" to "correct"))),
        )

    @Test
    fun `token is extracted by jsonpath and used as bearer token`() {
        val identity = context()
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { request ->
            val ok = String(request.body!!, Charsets.UTF_8).contains("\"password\":\"correct\"")
            TestJobs.response(if (ok) """{"token":"tok-abc"}""" else "{}", status = if (ok) 200 else 401)
        }
        val outcome = JsonLoginAuthenticator.authenticate(identity, run.http)
        assertThat(outcome).isEqualTo(AuthOutcome.Success)
        assertThat(identity.bearerToken).isEqualTo("tok-abc")
    }

    @Test
    fun `missing token field fails`() {
        val identity = context()
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { TestJobs.response("""{"status":"ok"}""") }
        val outcome = JsonLoginAuthenticator.authenticate(identity, run.http)
        assertThat(outcome).isInstanceOf(AuthOutcome.Failed::class.java)
        assertThat(identity.bearerToken).isNull()
    }

    @Test
    fun `non 2xx login response fails`() {
        val identity = context()
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { TestJobs.response("""{"error":"bad credentials"}""", status = 401) }
        assertThat(JsonLoginAuthenticator.authenticate(identity, run.http)).isInstanceOf(AuthOutcome.Failed::class.java)
    }

    @Test
    fun `missing tokenJsonPath configuration fails`() {
        val identity = context(config = mapOf("loginUrl" to "${TestJobs.BASE}/login"))
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { TestJobs.response("""{"token":"x"}""") }
        assertThat(JsonLoginAuthenticator.authenticate(identity, run.http)).isInstanceOf(AuthOutcome.Failed::class.java)
        assertThat(run.requests).isEmpty()
    }
}
