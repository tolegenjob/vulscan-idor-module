package io.vulscan.idor.report

import com.networknt.schema.InputFormat
import com.networknt.schema.SchemaLocation
import com.networknt.schema.SchemaRegistry
import com.networknt.schema.SpecificationVersion
import io.vulscan.idor.TestJobs
import io.vulscan.idor.check.AccessOutcome
import io.vulscan.idor.check.HorizontalCheckResult
import io.vulscan.idor.check.MarkerMatch
import io.vulscan.idor.check.MarkerMatchResult
import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.Envelope
import io.vulscan.kit.contracts.ExpectedAccess
import io.vulscan.kit.contracts.FindingPayload
import io.vulscan.kit.contracts.FindingReportedPayload
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.MessageType
import io.vulscan.kit.contracts.VulnType
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.worker.FindingSanitizer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

/** Все findings модуля должны соответствовать JSON-схеме finding-reported.v1 из kit. */
class IdorFindingContractTest {
    private val owner = TestJobs.identity("alice")
    private val attacker = TestJobs.identity("bob")
    private val endpoint = TestJobs.endpoint()
    private val resource = TestJobs.resource(endpoint, owner, listOf(AccessRuleRef(attacker.identityId, ExpectedAccess.DENY)))

    private val registry = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)

    private fun errors(finding: FindingPayload): List<String> {
        val envelope = Envelope(
            type = MessageType.FINDING_REPORTED,
            correlationId = UUID.randomUUID(),
            payload = FindingReportedPayload(UUID.randomUUID(), 1, FindingSanitizer.apply(finding)),
        )
        val schema = registry.getSchema(SchemaLocation.of("classpath:schemas/finding-reported.v1.json"))
        return schema.validate(Json.write(envelope), InputFormat.JSON).map { it.toString() }
    }

    private fun unauthorizedResult(repeatConfirmed: Boolean = true, markerRatio: Double = 1.0) = HorizontalCheckResult(
        resourceId = resource.resourceId,
        attackerId = attacker.identityId,
        outcome = AccessOutcome.UNAUTHORIZED_ACCESS,
        markerMatch = if (markerRatio >= 1.0) {
            MarkerMatchResult(listOf(MarkerMatch("$.ownerEmail", "alice@lab.test", "al***@lab.test")), 1)
        } else {
            MarkerMatchResult(emptyList(), 2)
        },
        repeatConfirmed = repeatConfirmed,
        anonymousStatus = 401,
        ownerStatus = 200,
        attackerRequest = ProbeRequest(HttpMethod.GET, "${TestJobs.BASE}/api/orders/1001", mapOf("Cookie" to "session=s3cr3t-bob")),
        attackerResponse = TestJobs.response("""{"id":1001,"ownerEmail":"alice@lab.test"}"""),
        denialSimilarity = 0.1,
    )

    @Test
    fun `confirmed horizontal finding conforms to the schema`() {
        val finding = IdorFindingFactory.create(
            endpoint, resource, VulnType.IDOR_HORIZONTAL, unauthorizedResult(),
            ownerLabel = owner.label, attackerLabel = attacker.label, ownerSessionOk = true, attackerSessionOk = true,
        )
        assertThat(finding).isNotNull
        assertThat(errors(finding!!)).isEmpty()
        assertThat(finding.verdict.name).isEqualTo("CONFIRMED")
    }

    @Test
    fun `likely finding with a partial marker match conforms to the schema`() {
        val finding = IdorFindingFactory.create(
            endpoint, resource, VulnType.IDOR_HORIZONTAL, unauthorizedResult(markerRatio = 0.5),
            ownerLabel = owner.label, attackerLabel = attacker.label, ownerSessionOk = true, attackerSessionOk = true,
        )
        assertThat(finding).isNotNull
        assertThat(errors(finding!!)).isEmpty()
        assertThat(finding.verdict.name).isEqualTo("LIKELY")
    }

    @Test
    fun `suspected structural finding with no owner markers conforms to the schema`() {
        val result = HorizontalCheckResult(
            resourceId = resource.resourceId,
            attackerId = attacker.identityId,
            outcome = AccessOutcome.AMBIGUOUS_STRUCTURE,
            markerMatch = MarkerMatchResult(emptyList(), 0),
            anonymousStatus = 401,
            ownerStatus = 200,
            attackerRequest = ProbeRequest(HttpMethod.GET, "${TestJobs.BASE}/api/orders/1001"),
            attackerResponse = TestJobs.response("""{"id":1002}"""),
            denialSimilarity = 0.3,
        )
        val finding = IdorFindingFactory.create(
            endpoint, resource, VulnType.IDOR_HORIZONTAL, result,
            ownerLabel = owner.label, attackerLabel = attacker.label, ownerSessionOk = true, attackerSessionOk = true,
        )
        assertThat(finding).isNotNull
        assertThat(errors(finding!!)).isEmpty()
        assertThat(finding.verdict.name).isEqualTo("SUSPECTED")
    }

    @Test
    fun `vertical finding conforms to the schema too`() {
        val finding = IdorFindingFactory.create(
            endpoint, resource, VulnType.IDOR_VERTICAL, unauthorizedResult(),
            ownerLabel = owner.label, attackerLabel = attacker.label, ownerSessionOk = true, attackerSessionOk = true,
        )
        assertThat(finding).isNotNull
        assertThat(errors(finding!!)).isEmpty()
    }

    @Test
    fun `an outcome that is not a finding produces no finding`() {
        val denied = unauthorizedResult().copy(outcome = AccessOutcome.DENIED)
        val finding = IdorFindingFactory.create(
            endpoint, resource, VulnType.IDOR_HORIZONTAL, denied,
            ownerLabel = owner.label, attackerLabel = attacker.label, ownerSessionOk = true, attackerSessionOk = true,
        )
        assertThat(finding).isNull()
    }
}
