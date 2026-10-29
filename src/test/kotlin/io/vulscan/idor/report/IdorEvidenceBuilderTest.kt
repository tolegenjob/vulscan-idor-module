package io.vulscan.idor.report

import io.vulscan.idor.TestJobs
import io.vulscan.idor.check.AccessOutcome
import io.vulscan.idor.check.HorizontalCheckResult
import io.vulscan.idor.check.MarkerMatch
import io.vulscan.idor.check.MarkerMatchResult
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.net.ProbeRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class IdorEvidenceBuilderTest {
    private fun result(
        request: ProbeRequest,
        response: io.vulscan.kit.net.ProbeResponse,
        markerMatch: MarkerMatchResult,
    ) = HorizontalCheckResult(
        resourceId = UUID.randomUUID(),
        attackerId = UUID.randomUUID(),
        outcome = AccessOutcome.UNAUTHORIZED_ACCESS,
        markerMatch = markerMatch,
        repeatConfirmed = true,
        anonymousStatus = 401,
        ownerStatus = 200,
        attackerRequest = request,
        attackerResponse = response,
        denialSimilarity = 0.12,
    )

    @Test
    fun `cookie and authorization headers never reach the evidence`() {
        val request = ProbeRequest(
            HttpMethod.GET, "${TestJobs.BASE}/api/orders/1001",
            headers = mapOf("Cookie" to "session=s3cr3t-bob", "Authorization" to "Bearer tok", "Accept" to "application/json"),
        )
        val response = TestJobs.response("""{"ownerEmail":"alice@lab.test"}""", headers = mapOf("Set-Cookie" to "x=1"))
        val match = MarkerMatchResult(listOf(MarkerMatch("$.ownerEmail", "alice@lab.test", "al***@lab.test")), 1)

        val evidence = IdorEvidenceBuilder.build(result(request, response, match))

        assertThat(evidence.request.headers.values).doesNotContain("session=s3cr3t-bob", "Bearer tok")
        assertThat(evidence.response!!.headers.values).doesNotContain("x=1")
    }

    @Test
    fun `the matched marker's real value is masked out of the response body excerpt`() {
        val request = ProbeRequest(HttpMethod.GET, "${TestJobs.BASE}/api/orders/1001")
        val response = TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}""")
        val match = MarkerMatchResult(listOf(MarkerMatch("$.ownerEmail", "alice@lab.test", "al***@lab.test")), 1)

        val evidence = IdorEvidenceBuilder.build(result(request, response, match))

        assertThat(evidence.response!!.bodyExcerpt).doesNotContain("alice@lab.test").contains("al***@lab.test")
    }

    @Test
    fun `identities are referenced in observations only by their visible fields, never an identity id`() {
        val request = ProbeRequest(HttpMethod.GET, "${TestJobs.BASE}/api/orders/1001")
        val response = TestJobs.response("""{"ownerEmail":"alice@lab.test"}""")
        val match = MarkerMatchResult(listOf(MarkerMatch("$.ownerEmail", "alice@lab.test", "al***@lab.test")), 1)

        val evidence = IdorEvidenceBuilder.build(result(request, response, match))

        assertThat(evidence.observations.map { it.key }).contains(
            "ownerBaselineStatus", "anonymousStatus", "attackerStatus", "markersMatched", "markersTotal", "repeatConfirmed", "denialShapeSimilarity",
        )
        val markersMatched = evidence.observations.single { it.key == "markersMatched" }.value
        assertThat(markersMatched).contains("al***@lab.test").doesNotContain("alice@lab.test")
    }

    @Test
    fun `the whole evidence stays well within the size cap`() {
        val request = ProbeRequest(HttpMethod.GET, "${TestJobs.BASE}/api/orders/1001")
        val response = TestJobs.response("{\"ownerEmail\":\"alice@lab.test\",\"junk\":\"${"x".repeat(5000)}\"}")
        val match = MarkerMatchResult(listOf(MarkerMatch("$.ownerEmail", "alice@lab.test", "al***@lab.test")), 1)

        val evidence = IdorEvidenceBuilder.build(result(request, response, match))

        val approxSize = (evidence.response?.bodyExcerpt?.length ?: 0) + evidence.observations.sumOf { it.key.length + it.value.length }
        assertThat(approxSize).isLessThan(16 * 1024)
    }
}
