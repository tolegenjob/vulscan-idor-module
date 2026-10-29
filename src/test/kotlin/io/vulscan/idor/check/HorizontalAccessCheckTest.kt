package io.vulscan.idor.check

import io.vulscan.idor.TestJobs
import io.vulscan.idor.TestJobs.endpoint
import io.vulscan.idor.TestJobs.identity
import io.vulscan.idor.TestRun
import io.vulscan.idor.auth.SessionManager
import io.vulscan.idor.identity.IdentityContext
import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.ExpectedAccess
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HorizontalAccessCheckTest {
    private val alice = identity("alice")
    private val bob = identity("bob")
    private val endpoint = endpoint()
    private val aliceCookie = "session=tok-alice"
    private val bobCookie = "session=tok-bob"
    private val nonexistentMarker = "2147483647" // id=1001 — числовой, см. ResourceRequestFactory.nonexistentValue

    private fun setup(maxReLoginAttempts: Int = 2, app: (ProbeRequest) -> ProbeResponse): Pair<HorizontalAccessCheck, TestRun> {
        val run = TestRun(TestJobs.job(listOf(endpoint), listOf(alice, bob), emptyList()), emptyList(), app)
        val sessions = SessionManager(maxReLoginAttempts = maxReLoginAttempts)
        return HorizontalAccessCheck(run.http, sessions) to run
    }

    private fun identityCtx(id: io.vulscan.kit.contracts.IdentityRef) = IdentityContext.from(TestJobs.credential(id))

    private fun resourceWith(expected: ExpectedAccess) =
        TestJobs.resource(endpoint, alice, listOf(AccessRuleRef(bob.identityId, expected)))

    @Test
    fun `attacker denied with 403 is classified as denied`() {
        val (check, _) = setup { req ->
            when (req.headers["Cookie"]) {
                aliceCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                bobCookie -> TestJobs.response("""{"error":"forbidden"}""", status = 403)
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = resourceWith(ExpectedAccess.DENY)
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(alice), identityCtx(bob))
        assertThat(result.outcome).isEqualTo(AccessOutcome.DENIED)
        assertThat(result.anonymousStatus).isEqualTo(401)
    }

    @Test
    fun `attacker who sees the owner's data twice is a confirmed unauthorized access`() {
        val (check, _) = setup { req ->
            when {
                req.url.contains(nonexistentMarker) -> TestJobs.response("""{"error":"not found"}""", status = 404)
                req.headers["Cookie"] == aliceCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                req.headers["Cookie"] == bobCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = resourceWith(ExpectedAccess.DENY)
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(alice), identityCtx(bob))
        assertThat(result.outcome).isEqualTo(AccessOutcome.UNAUTHORIZED_ACCESS)
        assertThat(result.repeatConfirmed).isTrue()
        assertThat(result.markerMatch?.any).isTrue()
    }

    @Test
    fun `a leak that does not repeat on the second probe is only ambiguous`() {
        var bobCalls = 0
        val (check, _) = setup { req ->
            when {
                req.url.contains(nonexistentMarker) -> TestJobs.response("""{"error":"not found"}""", status = 404)
                req.headers["Cookie"] == aliceCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                req.headers["Cookie"] == bobCookie -> {
                    bobCalls++
                    if (bobCalls == 1) TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                    else TestJobs.response("something else entirely, no json here", contentType = "text/plain")
                }
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = resourceWith(ExpectedAccess.DENY)
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(alice), identityCtx(bob))
        assertThat(result.outcome).isEqualTo(AccessOutcome.AMBIGUOUS)
        assertThat(result.repeatConfirmed).isFalse()
    }

    @Test
    fun `a legitimately allowed identity is reported as allowed, not as a finding`() {
        val (check, _) = setup { req ->
            when (req.headers["Cookie"]) {
                aliceCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                bobCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = resourceWith(ExpectedAccess.ALLOW)
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(alice), identityCtx(bob))
        assertThat(result.outcome).isEqualTo(AccessOutcome.ALLOWED_AS_EXPECTED)
    }

    @Test
    fun `a resource that leaks owner data anonymously is public, whatever the rule says`() {
        val (check, _) = setup { req ->
            when (req.headers["Cookie"]) {
                aliceCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                else -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
            }
        }
        val resource = resourceWith(ExpectedAccess.DENY)
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(alice), identityCtx(bob))
        assertThat(result.outcome).isEqualTo(AccessOutcome.PUBLIC_OBSERVED)
        assertThat(result.anonymousStatus).isEqualTo(200)
    }

    @Test
    fun `a failing owner baseline request makes the check inconclusive`() {
        val (check, _) = setup { req ->
            when (req.headers["Cookie"]) {
                aliceCookie -> TestJobs.response("""{"error":"boom"}""", status = 500)
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = resourceWith(ExpectedAccess.DENY)
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(alice), identityCtx(bob))
        assertThat(result.outcome).isEqualTo(AccessOutcome.ERROR)
        assertThat(result.inconclusiveReason).isEqualTo("OWNER_BASELINE_FAILED")
    }

    @Test
    fun `owner markers missing from the owner's own response also make the baseline fail`() {
        val (check, _) = setup { req ->
            when (req.headers["Cookie"]) {
                aliceCookie -> TestJobs.response("""{"id":1001}""") // ownerMarkers=$.ownerEmail отсутствует
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = resourceWith(ExpectedAccess.DENY)
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(alice), identityCtx(bob))
        assertThat(result.outcome).isEqualTo(AccessOutcome.ERROR)
        assertThat(result.inconclusiveReason).isEqualTo("OWNER_BASELINE_FAILED")
    }

    @Test
    fun `exhausted re-login attempts leave the attacker's probe inconclusive, not denied`() {
        val (check, _) = setup(maxReLoginAttempts = 0) { req ->
            when (req.headers["Cookie"]) {
                aliceCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                bobCookie -> TestJobs.response("""{"error":"session expired"}""", status = 401)
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = resourceWith(ExpectedAccess.DENY)
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(alice), identityCtx(bob))
        assertThat(result.outcome).isEqualTo(AccessOutcome.ERROR)
        assertThat(result.inconclusiveReason).isEqualTo("SESSION_EXPIRED")
    }
}
