package io.vulscan.idor.identity

import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.AuthSpec
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.ExpectedAccess
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.worker.JobContext
import io.vulscan.idor.TestJobs
import io.vulscan.idor.TestJobs.endpoint
import io.vulscan.idor.TestJobs.identity
import io.vulscan.idor.TestRun
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

class IdentityVaultTest {
    private val alice = identity("alice")
    private val bob = identity("bob")

    private fun job() = TestJobs.job(
        listOf(endpoint()), listOf(alice, bob),
        listOf(TestJobs.resource(endpoint(), alice, listOf(AccessRuleRef(bob.identityId, ExpectedAccess.DENY)))),
    )

    private fun run(app: (ProbeRequest) -> io.vulscan.kit.net.ProbeResponse = { TestJobs.response("{}") }) = TestRun(
        job(),
        listOf(
            TestJobs.credential(alice, secret = mapOf("cookie" to "session=s3cr3t-alice")),
            TestJobs.credential(bob, secret = mapOf("cookie" to "session=s3cr3t-bob")),
        ),
        app,
    )

    @Test
    fun `identities are fetched from Core exactly once per job`() {
        val calls = AtomicInteger()
        val base = run()
        val ctx = JobContext(base.ctx.job, base.http, base.stats, { }, { false }) {
            calls.incrementAndGet()
            listOf(TestJobs.credential(alice), TestJobs.credential(bob))
        }
        val vault = IdentityVault(ctx)
        vault.load()
        vault.load()
        vault.get(alice.identityId)
        assertThat(calls.get()).isEqualTo(1)
    }

    @Test
    fun `toString never reveals the secret`() {
        val run = run()
        val vault = IdentityVault(run.ctx)
        val aliceCtx = vault.load().getValue(alice.identityId)
        assertThat(aliceCtx.toString()).doesNotContain("s3cr3t-alice")
        assertThat(AuthSpec(AuthType.BEARER_STATIC, secret = mapOf("token" to "s3cr3t")).toString()).doesNotContain("s3cr3t")
    }

    @Test
    fun `secrets are zeroed after close`() {
        val run = run()
        val vault = IdentityVault(run.ctx)
        val aliceCtx = vault.load().getValue(alice.identityId)
        assertThat(aliceCtx.secret("cookie")).isEqualTo("session=s3cr3t-alice")
        vault.close()
        assertThat(aliceCtx.secret("cookie")).isEqualTo("")
    }

    @Test
    fun `each identity sends only its own static cookie`() {
        val run = run()
        val vault = IdentityVault(run.ctx)
        val aliceCtx = vault.load().getValue(alice.identityId)
        val bobCtx = vault.load().getValue(bob.identityId)
        val request = ProbeRequest(HttpMethod.GET, "${TestJobs.BASE}/api/me")

        aliceCtx.execute(run.http, request)
        assertThat(run.requests.last().headers["Cookie"]).isEqualTo("session=s3cr3t-alice")

        bobCtx.execute(run.http, request)
        assertThat(run.requests.last().headers["Cookie"]).isEqualTo("session=s3cr3t-bob")
    }

    @Test
    fun `a cookie the server grants to alice never reaches bob's request`() {
        val run = run { TestJobs.response("{}", headers = mapOf("Set-Cookie" to "serverGranted=alice-only")) }
        val vault = IdentityVault(run.ctx)
        val aliceCtx = vault.load().getValue(alice.identityId)
        val bobCtx = vault.load().getValue(bob.identityId)
        val request = ProbeRequest(HttpMethod.GET, "${TestJobs.BASE}/login")

        aliceCtx.execute(run.http, request) // Set-Cookie: serverGranted=alice-only попадает в cookie jar alice
        aliceCtx.execute(run.http, request)
        assertThat(run.requests.last().headers["Cookie"]).contains("serverGranted=alice-only")

        bobCtx.execute(run.http, request)
        val sentToBob = run.requests.last().headers["Cookie"]
        assertThat(sentToBob).doesNotContain("serverGranted").contains("session=s3cr3t-bob")
    }
}
