package io.vulscan.idor

import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.worker.AuthFailedException
import io.vulscan.kit.worker.DetectionEngine
import io.vulscan.kit.worker.InvalidJobException
import io.vulscan.kit.worker.JobContext
import io.vulscan.idor.auth.AuthOutcome
import io.vulscan.idor.auth.SessionManager
import io.vulscan.idor.config.IdorProperties
import io.vulscan.idor.identity.IdentityContext
import io.vulscan.idor.identity.IdentityVault
import io.vulscan.idor.identity.SessionState
import io.vulscan.idor.job.IdorJobValidator
import java.util.UUID

class IdorDetectionEngine(private val properties: IdorProperties = IdorProperties()) : DetectionEngine {
    override val moduleType = ModuleType.IDOR

    override fun run(ctx: JobContext) {
        val violations = IdorJobValidator.validate(ctx.job)
        if (violations.isNotEmpty()) throw InvalidJobException(violations.joinToString("; "))

        val idor = requireNotNull(ctx.job.moduleOptions.idor)
        val vault = IdentityVault(ctx)
        try {
            val identities = vault.load()
            val ids = idor.identities.map { it.identityId }
            val sessions = SessionManager(maxReLoginAttempts = properties.maxReLoginAttemptsPerIdentity)

            ids.forEach { id ->
                val identity = identities[id] ?: return@forEach
                if (sessions.establish(identity, ctx.http) is AuthOutcome.Failed) ctx.stats.inconclusive()
            }
            checkForIdentityCollisions(ctx, identities, ids, sessions)
            // Проверки доступа добавляются на следующих этапах (I-3…I-5).
        } finally {
            vault.close()
        }
    }

    /**
     * Запрашивает sessionCheck от имени каждой активной идентичности один раз: отмечает несовпавший
     * маркер как истёкшую сессию и, если две идентичности вернули один и тот же маркер, прерывает job.
     */
    private fun checkForIdentityCollisions(ctx: JobContext, identities: Map<UUID, IdentityContext>, ids: List<UUID>, sessions: SessionManager) {
        val check = ctx.job.moduleOptions.idor?.sessionCheck ?: return
        if (check.identityMarker == null) return
        val endpoint = ctx.job.endpoints.firstOrNull { it.endpointId == check.endpointId } ?: return

        val markers = mutableMapOf<UUID, String>()
        ids.forEach { id ->
            val identity = identities[id] ?: return@forEach
            if (identity.sessionState != SessionState.ACTIVE) return@forEach
            val outcome = sessions.readSessionCheck(identity, ctx.http, endpoint, check)
            if (!outcome.statusMatched || outcome.marker == null) {
                ctx.stats.inconclusive()
                identity.sessionState = SessionState.EXPIRED
                return@forEach
            }
            if (outcome.marker != identity.label) identity.sessionState = SessionState.EXPIRED
            markers[id] = outcome.marker
        }
        sessions.findIdentityCollision(markers)?.let { (a, b) ->
            throw AuthFailedException("identities ${identities[a]?.label} and ${identities[b]?.label} resolved to the same session")
        }
    }
}
