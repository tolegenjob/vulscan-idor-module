package io.vulscan.idor

import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.AuthSpec
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.ContractExamples
import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.ExpectedAccess
import io.vulscan.kit.contracts.FindingPayload
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.IdentityCredential
import io.vulscan.kit.contracts.IdentityRef
import io.vulscan.kit.contracts.IdorMode
import io.vulscan.kit.contracts.IdorOptions
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.ParameterId
import io.vulscan.kit.contracts.ParameterRef
import io.vulscan.kit.contracts.ResourceRef
import io.vulscan.kit.contracts.ScanJobPayload
import io.vulscan.kit.contracts.Sensitivity
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.kit.worker.BudgetedHttp
import io.vulscan.kit.worker.JobContext
import io.vulscan.kit.worker.MutableJobStats
import io.vulscan.kit.worker.RateLimiter
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList

object TestJobs {
    const val BASE = "http://lab-app:8080"

    fun baseJob(): ScanJobPayload =
        Json.payloadAs(Json.readEnvelope(ContractExamples.valid("scan-job-idor.json")), ScanJobPayload::class.java)
            .copy(deadlineAt = Instant.now().plusSeconds(3600))

    fun endpoint(
        url: String = "$BASE/api/orders/{id}",
        method: HttpMethod = HttpMethod.GET,
        parameters: Array<ParameterRef> = arrayOf(ParameterRef("id", ParamLocation.PATH, "1001")),
    ) = EndpointRef(UUID.randomUUID(), method, url, true, parameters.toList())

    fun identity(label: String, role: String = "USER", identityId: UUID = UUID.randomUUID()) = IdentityRef(identityId, label, role)

    fun resource(
        endpoint: EndpointRef,
        owner: IdentityRef,
        access: List<AccessRuleRef>,
        sensitivity: Sensitivity = Sensitivity.MEDIUM,
        ownerMarkers: List<String> = listOf("$.ownerEmail"),
        idParameter: ParameterId = ParameterId("id", ParamLocation.PATH),
        idValue: String = "1001",
    ) = ResourceRef(UUID.randomUUID(), endpoint.endpointId, idParameter, idValue, owner.identityId, sensitivity, ownerMarkers, access)

    fun job(
        endpoints: List<EndpointRef>,
        identities: List<IdentityRef>,
        resources: List<ResourceRef>,
        mode: IdorMode = IdorMode.READ_ONLY,
        maxRequests: Int = 600,
    ): ScanJobPayload {
        val base = baseJob()
        return base.copy(
            endpoints = endpoints,
            moduleOptions = base.moduleOptions.copy(idor = IdorOptions(mode, identities, resources)),
            limits = base.limits.copy(maxRequests = maxRequests, requestsPerSecond = 1000, maxConcurrency = 4),
        )
    }

    fun credential(
        identity: IdentityRef,
        authType: AuthType = AuthType.COOKIE_STATIC,
        config: Map<String, String> = emptyMap(),
        secret: Map<String, String> = mapOf("cookie" to "session=tok-${identity.label}"),
    ) = IdentityCredential(identity.identityId, identity.label, identity.role, AuthSpec(authType, config, secret))

    fun response(
        body: String,
        status: Int = 200,
        contentType: String? = "application/json",
        headers: Map<String, String> = emptyMap(),
    ) = ProbeResponse(
        status = status,
        headers = buildMap {
            putAll(headers.mapKeys { it.key.lowercase() })
            if (contentType != null) put("content-type", contentType)
        },
        body = body.toByteArray(Charsets.UTF_8),
        truncated = false,
        elapsedMs = 1,
        finalUrl = BASE,
        redirectChain = emptyList(),
    )
}

/** Контекст задания для тестов: запросы уходят в [app], найденные уязвимости собираются в [findings]. */
class TestRun(job: ScanJobPayload, app: (ProbeRequest) -> ProbeResponse, identities: List<IdentityCredential> = emptyList()) {
    val requests = CopyOnWriteArrayList<ProbeRequest>()
    val findings = CopyOnWriteArrayList<FindingPayload>()
    val stats = MutableJobStats()
    val http = BudgetedHttp(
        delegate = { request ->
            requests += request
            app(request)
        },
        rateLimiter = RateLimiter(1000),
        maxRequests = job.limits.maxRequests,
        maxConcurrency = job.limits.maxConcurrency,
        deadline = job.deadlineAt,
        isCancelled = { false },
    )
    val ctx = JobContext(job, http, stats, { findings += it }, { false }, { identities })
}
