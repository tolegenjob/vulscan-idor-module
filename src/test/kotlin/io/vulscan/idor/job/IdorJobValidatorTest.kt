package io.vulscan.idor.job

import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.ExpectedAccess
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.IdorMode
import io.vulscan.kit.contracts.IdorOptions
import io.vulscan.idor.TestJobs
import io.vulscan.idor.TestJobs.endpoint
import io.vulscan.idor.TestJobs.identity
import io.vulscan.idor.TestJobs.resource
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class IdorJobValidatorTest {
    private val alice = identity("alice")
    private val bob = identity("bob")

    @Test
    fun `valid job with GET endpoint and known identities is accepted`() {
        val ep = endpoint()
        val res = resource(ep, alice, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)))
        val job = TestJobs.job(listOf(ep), listOf(alice, bob), listOf(res))
        assertThat(IdorJobValidator.validate(job)).isEmpty()
    }

    @Test
    fun `HEAD endpoint is allowed in read only mode`() {
        val ep = endpoint(method = HttpMethod.HEAD)
        val res = resource(ep, alice, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)))
        val job = TestJobs.job(listOf(ep), listOf(alice, bob), listOf(res))
        assertThat(IdorJobValidator.validate(job)).isEmpty()
    }

    @Test
    fun `PUT endpoint is rejected in read only mode`() {
        val ep = endpoint(method = HttpMethod.PUT)
        val res = resource(ep, alice, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)))
        val job = TestJobs.job(listOf(ep), listOf(alice, bob), listOf(res))
        assertThat(IdorJobValidator.validate(job)).anyMatch { it.contains("READ_ONLY") }
    }

    @Test
    fun `access rule referring to an identity outside the matrix is rejected`() {
        val ep = endpoint()
        val stranger = UUID.randomUUID()
        val res = resource(ep, alice, listOf(AccessRuleRef(stranger, ExpectedAccess.DENY)))
        val job = TestJobs.job(listOf(ep), listOf(alice, bob), listOf(res))
        assertThat(IdorJobValidator.validate(job)).anyMatch { it.contains("unknown identity") }
    }

    @Test
    fun `resource without a known owner is rejected`() {
        val ep = endpoint()
        val res = resource(ep, identity("carol"), listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)))
        val job = TestJobs.job(listOf(ep), listOf(alice, bob), listOf(res))
        assertThat(IdorJobValidator.validate(job)).anyMatch { it.contains("owner is not in identities") }
    }

    @Test
    fun `resource without access rules is rejected`() {
        val ep = endpoint()
        val res = resource(ep, alice, emptyList())
        val job = TestJobs.job(listOf(ep), listOf(alice, bob), listOf(res))
        assertThat(IdorJobValidator.validate(job)).anyMatch { it.contains("no access rules") }
    }

    @Test
    fun `job without resources is rejected`() {
        val job = TestJobs.job(listOf(endpoint()), listOf(alice, bob), emptyList())
        assertThat(IdorJobValidator.validate(job)).anyMatch { it.contains("resources must not be empty") }
    }

    @Test
    fun `resource endpoint missing from the job is rejected`() {
        val ep = endpoint()
        val foreign = endpoint(url = "${TestJobs.BASE}/api/other/{id}")
        val res = resource(foreign, alice, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)))
        val job = TestJobs.job(listOf(ep), listOf(alice, bob), listOf(res))
        assertThat(IdorJobValidator.validate(job)).anyMatch { it.contains("is not in job.endpoints") }
    }

    @Test
    fun `job without idor options is rejected`() {
        val ep = endpoint()
        val res = resource(ep, alice, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)))
        val base = TestJobs.job(listOf(ep), listOf(alice, bob), listOf(res))
        val job = base.copy(moduleOptions = base.moduleOptions.copy(idor = null))
        assertThat(IdorJobValidator.validate(job)).anyMatch { it.contains("moduleOptions.idor") }
    }

    @Test
    fun `resources without owner markers are reported for the engine to cap at SUSPECTED later`() {
        val ep = endpoint()
        val res = resource(ep, alice, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)), ownerMarkers = emptyList())
        val options = IdorOptions(IdorMode.READ_ONLY, listOf(alice, bob), listOf(res))
        assertThat(IdorJobValidator.resourcesMissingMarkers(options)).containsExactly(res.resourceId)
    }
}
