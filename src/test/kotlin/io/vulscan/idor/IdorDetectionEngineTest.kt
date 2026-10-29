package io.vulscan.idor

import io.vulscan.idor.TestJobs.endpoint
import io.vulscan.idor.TestJobs.identity
import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.ExpectedAccess
import io.vulscan.kit.contracts.VulnType
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** Сквозной прогон движка на фейковом HTTP: проверяет, что I-3/I-4/I-5 действительно соединены внутри run(). */
class IdorDetectionEngineTest {
    private val alice = identity("alice", role = "USER")
    private val bob = identity("bob", role = "USER")
    private val admin = identity("admin", role = "ADMIN")

    private val aliceCookie = "session=tok-alice"
    private val bobCookie = "session=tok-bob"
    private val adminCookie = "session=tok-admin"
    private val nonexistentMarker = "2147483647"

    @Test
    fun `a horizontal leak between two users is reported as an IDOR_HORIZONTAL finding`() {
        val endpoint = endpoint()
        val resource = TestJobs.resource(endpoint, alice, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)))
        val run = TestRun(
            TestJobs.job(listOf(endpoint), listOf(alice, bob), listOf(resource)),
            listOf(TestJobs.credential(alice), TestJobs.credential(bob)),
        ) { req ->
            when {
                req.url.contains(nonexistentMarker) -> TestJobs.response("""{"error":"not found"}""", status = 404)
                req.headers["Cookie"] == aliceCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                req.headers["Cookie"] == bobCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }

        IdorDetectionEngine().run(run.ctx)

        assertThat(run.findings).hasSize(1)
        val finding = run.findings.single()
        assertThat(finding.vulnType).isEqualTo(VulnType.IDOR_HORIZONTAL)
        assertThat(finding.verdict.name).isEqualTo("CONFIRMED")
    }

    @Test
    fun `a correctly denied user produces no finding and is not counted as inconclusive`() {
        val endpoint = endpoint()
        val resource = TestJobs.resource(endpoint, alice, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)))
        val run = TestRun(
            TestJobs.job(listOf(endpoint), listOf(alice, bob), listOf(resource)),
            listOf(TestJobs.credential(alice), TestJobs.credential(bob)),
        ) { req ->
            when (req.headers["Cookie"]) {
                aliceCookie -> TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
                bobCookie -> TestJobs.response("""{"error":"forbidden"}""", status = 403)
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }

        IdorDetectionEngine().run(run.ctx)

        assertThat(run.findings).isEmpty()
        assertThat(run.stats.snapshot(0, 0).inconclusive).isEqualTo(0)
    }

    @Test
    fun `a user who sees the admin listing is reported as an IDOR_VERTICAL finding`() {
        val endpoint = endpoint(url = "${TestJobs.BASE}/api/admin/users/{id}")
        val resource = TestJobs.resource(
            endpoint, admin, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)),
            ownerMarkers = listOf("$.users[0]"),
        )
        val run = TestRun(
            TestJobs.job(listOf(endpoint), listOf(admin, bob), listOf(resource)),
            listOf(TestJobs.credential(admin), TestJobs.credential(bob)),
        ) { req ->
            when {
                req.url.contains(nonexistentMarker) -> TestJobs.response("""{"error":"not found"}""", status = 404)
                req.headers["Cookie"] == adminCookie -> TestJobs.response("""{"users":["alice@lab.test"]}""")
                req.headers["Cookie"] == bobCookie -> TestJobs.response("""{"users":["alice@lab.test"]}""")
                else -> TestJobs.response("""{"error":"unauthorized"}""", status = 401)
            }
        }

        IdorDetectionEngine().run(run.ctx)

        assertThat(run.findings).hasSize(1)
        assertThat(run.findings.single().vulnType).isEqualTo(VulnType.IDOR_VERTICAL)
    }

    @Test
    fun `an owner listed in their own access rule is never attacked against themselves`() {
        val endpoint = endpoint()
        val resource = TestJobs.resource(endpoint, alice, listOf(AccessRuleRef(alice.identityId, ExpectedAccess.ALLOW)))
        val run = TestRun(
            TestJobs.job(listOf(endpoint), listOf(alice), listOf(resource)),
            listOf(TestJobs.credential(alice)),
        ) { TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""") }

        IdorDetectionEngine().run(run.ctx)

        assertThat(run.findings).isEmpty()
    }
}
