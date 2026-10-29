package io.vulscan.idor.check

import io.vulscan.idor.TestJobs
import io.vulscan.idor.compare.ResponseSignature
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ResponseClassifierTest {
    private val ownerJson = """{"id":1,"ownerEmail":"alice@lab.test"}"""
    private val denialJson = """{"error":"not found"}"""
    private val ownerResponse = TestJobs.response(ownerJson)
    private val denialShape = DenialShape.of(TestJobs.response(denialJson, status = 404))
    private val ownerSignature = ResponseSignature.of(ownerResponse)
    private val noMatch = MarkerMatchResult(emptyList(), 1)
    private val oneMatch = MarkerMatchResult(listOf(MarkerMatch("$.ownerEmail", "al***@lab.test")), 1)

    private fun classify(response: io.vulscan.kit.net.ProbeResponse, match: MarkerMatchResult = noMatch, loginUrl: String? = "/login") =
        ResponseClassifier.classify(response, ownerSignature, denialShape.signature, match, loginUrl, 0.90)

    @Test
    fun `401 is denied`() {
        assertThat(classify(TestJobs.response("", status = 401))).isEqualTo(AccessOutcome.DENIED)
    }

    @Test
    fun `403 is denied`() {
        assertThat(classify(TestJobs.response("", status = 403))).isEqualTo(AccessOutcome.DENIED)
    }

    @Test
    fun `404 is denied hidden`() {
        assertThat(classify(TestJobs.response("", status = 404))).isEqualTo(AccessOutcome.DENIED_HIDDEN)
    }

    @Test
    fun `410 is denied hidden`() {
        assertThat(classify(TestJobs.response("", status = 410))).isEqualTo(AccessOutcome.DENIED_HIDDEN)
    }

    @Test
    fun `redirect to the configured login url is auth required`() {
        val response = TestJobs.response("", status = 302, headers = mapOf("Location" to "https://lab.test/login?next=%2Forders"))
        assertThat(classify(response)).isEqualTo(AccessOutcome.AUTH_REQUIRED)
    }

    @Test
    fun `redirect is auth required when no login url is configured to compare against`() {
        val response = TestJobs.response("", status = 302, headers = mapOf("Location" to "https://lab.test/somewhere"))
        assertThat(classify(response, loginUrl = null)).isEqualTo(AccessOutcome.AUTH_REQUIRED)
    }

    @Test
    fun `redirect elsewhere while a login url is configured is not auth required`() {
        val response = TestJobs.response("", status = 302, headers = mapOf("Location" to "https://lab.test/orders/1001/pdf"))
        assertThat(classify(response)).isEqualTo(AccessOutcome.AMBIGUOUS)
    }

    @Test
    fun `500 is an error`() {
        assertThat(classify(TestJobs.response("", status = 500))).isEqualTo(AccessOutcome.ERROR)
    }

    @Test
    fun `503 is an error`() {
        assertThat(classify(TestJobs.response("", status = 503))).isEqualTo(AccessOutcome.ERROR)
    }

    @Test
    fun `2xx with any owner marker found is unauthorized access`() {
        val response = TestJobs.response("""{"id":1,"ownerEmail":"alice@lab.test"}""")
        assertThat(classify(response, match = oneMatch)).isEqualTo(AccessOutcome.UNAUTHORIZED_ACCESS)
    }

    @Test
    fun `2xx with a partial marker match is still unauthorized access`() {
        val partial = MarkerMatchResult(listOf(MarkerMatch("$.ownerEmail", "al***@lab.test")), 2)
        assertThat(classify(TestJobs.response("""{"ownerEmail":"alice@lab.test"}"""), match = partial)).isEqualTo(AccessOutcome.UNAUTHORIZED_ACCESS)
    }

    @Test
    fun `2xx with no markers but a body matching the denial shape is denied soft`() {
        val response = TestJobs.response(denialJson)
        assertThat(classify(response)).isEqualTo(AccessOutcome.DENIED_SOFT)
    }

    @Test
    fun `2xx with no markers but the same structure as the owner response is ambiguous structure`() {
        val response = TestJobs.response("""{"id":2,"ownerEmail":"bob@lab.test"}""")
        assertThat(classify(response)).isEqualTo(AccessOutcome.AMBIGUOUS_STRUCTURE)
    }

    @Test
    fun `2xx matching neither owner nor denial shape is ambiguous`() {
        val response = TestJobs.response("plain text response with nothing recognisable", contentType = "text/plain")
        assertThat(classify(response)).isEqualTo(AccessOutcome.AMBIGUOUS)
    }

    @Test
    fun `an unexpected status outside the known ranges is ambiguous`() {
        assertThat(classify(TestJobs.response("", status = 418))).isEqualTo(AccessOutcome.AMBIGUOUS)
    }
}
