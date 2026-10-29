package io.vulscan.idor.config

import io.vulscan.kit.worker.WorkerProperties

/** Настройки модуля (переменные окружения, см. README). */
data class IdorProperties(
    val maxReLoginAttemptsPerIdentity: Int = 2,
    val healthPort: Int = 8081,
    /** Порог похожести ответа на "форму отказа" (DenialShape), выше которого считаем доступ отказанным (DENIED_SOFT). */
    val denialSimilarityThreshold: Double = 0.90,
) {
    init {
        require(maxReLoginAttemptsPerIdentity in 0..5) { "maxReLoginAttemptsPerIdentity must be within 0..5" }
        require(denialSimilarityThreshold in 0.0..1.0) { "denialSimilarityThreshold must be within 0.0..1.0" }
    }

    companion object {
        fun fromEnv(env: Map<String, String>) = IdorProperties(
            maxReLoginAttemptsPerIdentity = env["IDOR_MAX_RELOGIN_ATTEMPTS"]?.toIntOrNull() ?: 2,
            healthPort = env["HEALTH_PORT"]?.toIntOrNull() ?: 8081,
            denialSimilarityThreshold = env["IDOR_DENIAL_SIMILARITY_THRESHOLD"]?.toDoubleOrNull() ?: 0.90,
        )

        fun workerFromEnv(env: Map<String, String>): WorkerProperties {
            fun required(name: String) = env[name]?.takeIf { it.isNotBlank() } ?: error("Environment variable $name is required")
            return WorkerProperties(
                coreBaseUrl = required("WORKER_CORE_BASE_URL"),
                serviceToken = required("WORKER_SERVICE_TOKEN"),
                bootstrapServers = env["KAFKA_BOOTSTRAP_SERVERS"] ?: "kafka:9092",
                consumerGroup = env["WORKER_CONSUMER_GROUP"] ?: "idor-module",
                workerId = env["WORKER_ID"] ?: ("idor-" + java.util.UUID.randomUUID().toString().take(8)),
                maxConcurrentJobs = env["WORKER_MAX_CONCURRENT_JOBS"]?.toIntOrNull() ?: 2,
                allowedPrivateCidrs = env["WORKER_ALLOWED_PRIVATE_CIDRS"]
                    ?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList(),
            )
        }
    }
}
