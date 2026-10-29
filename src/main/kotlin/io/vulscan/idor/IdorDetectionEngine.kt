package io.vulscan.idor

import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.worker.DetectionEngine
import io.vulscan.kit.worker.InvalidJobException
import io.vulscan.kit.worker.JobContext
import io.vulscan.idor.config.IdorProperties
import io.vulscan.idor.identity.IdentityVault
import io.vulscan.idor.job.IdorJobValidator

class IdorDetectionEngine(private val properties: IdorProperties = IdorProperties()) : DetectionEngine {
    override val moduleType = ModuleType.IDOR

    override fun run(ctx: JobContext) {
        val violations = IdorJobValidator.validate(ctx.job)
        if (violations.isNotEmpty()) throw InvalidJobException(violations.joinToString("; "))

        val vault = IdentityVault(ctx)
        try {
            vault.load()
            // Проверки доступа добавляются на следующих этапах (I-2…I-5).
        } finally {
            vault.close()
        }
    }
}
