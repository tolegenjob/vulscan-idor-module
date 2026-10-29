package io.vulscan.idor.identity

import io.vulscan.kit.worker.JobContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Секреты идентичностей задания: получаются у Core ровно один раз и хранятся только в памяти.
 * [close] явно обнуляет секреты — вызывается после завершения задания независимо от исхода.
 */
class IdentityVault(private val ctx: JobContext) {
    private val contexts = ConcurrentHashMap<UUID, IdentityContext>()
    private var loaded = false

    @Synchronized
    fun load(): Map<UUID, IdentityContext> {
        if (!loaded) {
            ctx.identities().forEach { credential -> contexts[credential.identityId] = IdentityContext.from(credential) }
            loaded = true
        }
        return contexts
    }

    fun get(identityId: UUID): IdentityContext = contexts[identityId] ?: error("Unknown identity $identityId")

    fun close() {
        contexts.values.forEach { it.clear() }
    }
}
