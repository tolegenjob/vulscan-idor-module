package io.vulscan.idor.job

import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.IdorMode
import io.vulscan.kit.contracts.IdorOptions
import io.vulscan.kit.contracts.ScanJobPayload
import java.util.UUID

/**
 * Проверки, специфичные для IDOR-модуля. Многое (≥2 identities, READ_ONLY⇒GET/HEAD, ссылки на
 * неизвестные identity/endpoint) уже отклоняет общий [io.vulscan.kit.contracts.ScanJobPayloadValidator]
 * до того, как задание попадёт в модуль; здесь проверяется то, что он не покрывает.
 */
object IdorJobValidator {
    fun validate(job: ScanJobPayload): List<String> {
        val idor = job.moduleOptions.idor ?: return listOf("moduleOptions.idor is missing")
        val violations = mutableListOf<String>()
        val identityIds = idor.identities.map { it.identityId }.toSet()
        val endpointIds = job.endpoints.map { it.endpointId }.toSet()
        val endpointById = job.endpoints.associateBy { it.endpointId }

        if (idor.resources.isEmpty()) violations += "idor.resources must not be empty"

        idor.resources.forEach { resource ->
            if (resource.access.isEmpty()) violations += "resource ${resource.resourceId} has no access rules"
            if (resource.ownerIdentityId !in identityIds) violations += "resource ${resource.resourceId} owner is not in identities"
            resource.access.filter { it.identityId !in identityIds }.forEach {
                violations += "resource ${resource.resourceId} access rule refers to unknown identity"
            }
            if (resource.endpointId !in endpointIds) {
                violations += "resource ${resource.resourceId} endpoint ${resource.endpointId} is not in job.endpoints"
            }
            if (idor.mode == IdorMode.READ_ONLY) {
                val method = endpointById[resource.endpointId]?.method
                if (method != null && method != HttpMethod.GET && method != HttpMethod.HEAD) {
                    violations += "resource ${resource.resourceId} endpoint uses $method in READ_ONLY mode"
                }
            }
        }

        idor.sessionCheck?.let { check ->
            if (check.endpointId !in endpointIds) violations += "sessionCheck endpoint ${check.endpointId} is not in job.endpoints"
        }

        idor.discovery.forEach { rule ->
            if (rule.endpointId !in endpointIds) violations += "discovery rule endpoint ${rule.endpointId} is not in job.endpoints"
            if (rule.identityId !in identityIds) violations += "discovery rule refers to unknown identity"
        }

        return violations
    }

    /** Ресурсы без ownerMarkers: проверка допускается, но итог не выше SUSPECTED (см. I-5). */
    fun resourcesMissingMarkers(idor: IdorOptions): Set<UUID> =
        idor.resources.filter { it.ownerMarkers.isEmpty() }.map { it.resourceId }.toSet()
}
