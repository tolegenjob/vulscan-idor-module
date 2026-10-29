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
import io.vulscan.idor.identity.SessionState
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

class SessionManagerTest {
    private fun formIdentity() = IdentityContext.from(
        IdentityCredential(
            identity("alice").identityId, "alice", "USER",
            AuthSpec(AuthType.FORM_LOGIN, mapOf("loginUrl" to "${TestJobs.BASE}/login"), mapOf("username" to "alice", "password" to "correct")),
        ),
    )

    private fun protectedRequest() = ProbeRequest(HttpMethod.GET, "${TestJobs.BASE}/api/orders/1001")

    @Test
    fun `session that expires on the fifth request gets one re-login and the check continues`() {
        val identity = formIdentity()
        val calls = AtomicInteger()
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { request ->
            when {
                request.url.endsWith("/login") -> TestJobs.response("ok")
                calls.incrementAndGet() == 5 -> TestJobs.response("expired", status = 401)
                else -> TestJobs.response("{\"data\":1}")
            }
        }
        val sessions = SessionManager()
        sessions.establish(identity, run.http)
        repeat(4) { assertThat(sessions.execute(identity, run.http, protectedRequest())).isInstanceOf(SessionResult.Ok::class.java) }
        val fifth = sessions.execute(identity, run.http, protectedRequest())
        assertThat(fifth).isInstanceOf(SessionResult.Ok::class.java) // повторный вход восстановил сессию
        assertThat(identity.sessionState).isEqualTo(SessionState.ACTIVE)
    }

    @Test
    fun `when re-login does not help the identity becomes EXPIRED and further checks are inconclusive`() {
        val identity = formIdentity()
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { request ->
            if (request.url.endsWith("/login")) TestJobs.response("still rejected", status = 401) else TestJobs.response("expired", status = 401)
        }
        val sessions = SessionManager()
        val result = sessions.execute(identity, run.http, protectedRequest())
        assertThat(result).isEqualTo(SessionResult.Expired)
        assertThat(identity.sessionState).isEqualTo(SessionState.EXPIRED)
    }

    @Test
    fun `re-login attempts are capped per identity for the whole job`() {
        val identity = formIdentity()
        var loginCalls = 0
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { request ->
            if (request.url.endsWith("/login")) {
                loginCalls++
                TestJobs.response("ok")
            } else {
                TestJobs.response("expired", status = 401)
            }
        }
        val sessions = SessionManager(maxReLoginAttempts = 2)
        sessions.execute(identity, run.http, protectedRequest())
        sessions.execute(identity, run.http, protectedRequest())
        val third = sessions.execute(identity, run.http, protectedRequest())
        assertThat(third).isEqualTo(SessionResult.Expired)
        assertThat(loginCalls).isEqualTo(2)
    }

    @Test
    fun `redirect to the login url also counts as an expired session`() {
        val identity = formIdentity()
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { request ->
            when {
                request.url.endsWith("/login") -> TestJobs.response("ok")
                else -> TestJobs.response("", status = 302, headers = mapOf("Location" to "${TestJobs.BASE}/login"))
            }
        }
        val result = SessionManager().execute(identity, run.http, protectedRequest())
        assertThat(result).isEqualTo(SessionResult.Expired)
    }

    @Test
    fun `static credentials never attempt a re-login`() {
        val identity = IdentityContext.from(IdentityCredential(identity("alice").identityId, "alice", "USER", AuthSpec(AuthType.BEARER_STATIC, secret = mapOf("token" to "static-tok"))))
        var requests = 0
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { requests++; TestJobs.response("expired", status = 401) }
        val result = SessionManager().execute(identity, run.http, protectedRequest())
        assertThat(result).isEqualTo(SessionResult.Expired)
        assertThat(requests).isEqualTo(2) // исходный запрос + одна безуспешная попытка «повторного входа»
    }

    @Test
    fun `password never appears in the authenticator's exception messages`() {
        val identity = formIdentity()
        val run = TestRun(TestJobs.job(listOf(), listOf(), listOf())) { TestJobs.response("nope", status = 403) }
        val outcome = FormLoginAuthenticator.authenticate(identity, run.http) as AuthOutcome.Failed
        assertThat(outcome.reason).doesNotContain("correct")
    }
}
