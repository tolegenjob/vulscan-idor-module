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

class VerticalAccessCheckTest {
    private val admin = identity("admin", role = "ADMIN")
    private val user = identity("user", role = "USER")
    private val endpoint = endpoint(url = "${TestJobs.BASE}/api/admin/users/{id}")
    private val adminCookie = "session=tok-admin"
    private val userCookie = "session=tok-user"
    private val nonexistentMarker = "2147483647"

    private fun setup(app: (ProbeRequest) -> ProbeResponse): VerticalAccessCheck {
        val run = TestRun(TestJobs.job(listOf(endpoint), listOf(admin, user), emptyList()), emptyList(), app)
        val horizontal = HorizontalAccessCheck(run.http, SessionManager(maxReLoginAttempts = 2))
        return VerticalAccessCheck(horizontal)
    }

    private fun identityCtx(id: io.vulscan.kit.contracts.IdentityRef) = IdentityContext.from(TestJobs.credential(id))

    private fun resource() = TestJobs.resource(endpoint, admin, listOf(AccessRuleRef(user.identityId, ExpectedAccess.DENY)))

    @Test
    fun `a user who sees the admin-only listing twice is a confirmed vertical escalation`() {
        val check = setup { req ->
            when {
                req.url.contains(nonexistentMarker) -> TestJobs.response("""{"error":"not found"}""", status = 404)
                req.headers["Cookie"] == adminCookie -> TestJobs.response("""{"users":["alice@lab.test","bob@lab.test"]}""")
                req.headers["Cookie"] == userCookie -> TestJobs.response("""{"users":["alice@lab.test","bob@lab.test"]}""")
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = TestJobs.resource(
            endpoint, admin, listOf(AccessRuleRef(user.identityId, ExpectedAccess.DENY)),
            ownerMarkers = listOf("$.users[0]"),
        )
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(admin), identityCtx(user))
        assertThat(result).isNotNull
        assertThat(result!!.outcome).isEqualTo(AccessOutcome.UNAUTHORIZED_ACCESS)
        assertThat(result.repeatConfirmed).isTrue()
    }

    @Test
    fun `a user correctly refused the admin function produces no outcome worth a finding`() {
        val check = setup { req ->
            when (req.headers["Cookie"]) {
                adminCookie -> TestJobs.response("""{"users":["alice@lab.test"]}""")
                userCookie -> TestJobs.response("""{"error":"forbidden"}""", status = 403)
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = resource()
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(admin), identityCtx(user))
        assertThat(result!!.outcome).isEqualTo(AccessOutcome.DENIED)
    }

    @Test
    fun `the reference identity itself failing the baseline is inconclusive, not a finding`() {
        val check = setup { req ->
            when (req.headers["Cookie"]) {
                adminCookie -> TestJobs.response("""{"error":"boom"}""", status = 500)
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }
        val resource = resource()
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(admin), identityCtx(user))
        assertThat(result!!.outcome).isEqualTo(AccessOutcome.ERROR)
        assertThat(result.inconclusiveReason).isEqualTo("OWNER_BASELINE_FAILED")
    }

    @Test
    fun `a role that is not lower than the reference role is never even probed`() {
        val check = setup { error("no request should have been sent") }
        val resource = TestJobs.resource(endpoint, admin, listOf(AccessRuleRef(admin.identityId, ExpectedAccess.ALLOW)))
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(admin), identityCtx(admin))
        assertThat(result).isNull()
    }

    @Test
    fun `an unknown role is never comparable either`() {
        val guest = identity("guest", role = "GUEST_WITH_NO_KNOWN_ORDER")
        val check = setup { error("no request should have been sent") }
        val resource = TestJobs.resource(endpoint, admin, listOf(AccessRuleRef(guest.identityId, ExpectedAccess.DENY)))
        val result = check.check(endpoint, resource, resource.access.single(), identityCtx(admin), identityCtx(guest))
        assertThat(result).isNull()
    }
}
