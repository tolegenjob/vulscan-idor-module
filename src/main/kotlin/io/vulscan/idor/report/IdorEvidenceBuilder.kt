package io.vulscan.idor.report

import io.vulscan.idor.check.HorizontalCheckResult
import io.vulscan.idor.check.MarkerMatchResult
import io.vulscan.kit.contracts.Evidence
import io.vulscan.kit.contracts.HttpRequestEvidence
import io.vulscan.kit.contracts.HttpResponseEvidence
import io.vulscan.kit.contracts.Observation
import io.vulscan.kit.redact.Redactor

/**
 * Собирает [Evidence] из результата проверки доступа: запрос/ответ решающей пробы атакующей identity плюс
 * наблюдения (owner baseline, anonymous control, повторность). [io.vulscan.kit.worker.FindingSanitizer]
 * маскирует секреты повторно перед публикацией — здесь маскируются именно значения найденных маркеров,
 * которых сам Sanitizer не знает.
 */
object IdorEvidenceBuilder {
    private const val MAX_BODY_EXCERPT = 2048

    fun build(result: HorizontalCheckResult): Evidence {
        val request = result.attackerRequest
        val response = result.attackerResponse
        val markerMatch = result.markerMatch ?: MarkerMatchResult(emptyList(), 0)

        val requestEvidence = HttpRequestEvidence(
            method = request?.method ?: io.vulscan.kit.contracts.HttpMethod.GET,
            url = request?.url ?: "",
            headers = Redactor.headers(request?.headers ?: emptyMap()),
        )
        val responseEvidence = response?.let {
            HttpResponseEvidence(
                status = it.status,
                headers = Redactor.headers(it.headers),
                bodyExcerpt = Redactor.excerpt(maskMarkers(it.bodyText(), markerMatch), MAX_BODY_EXCERPT),
            )
        }

        return Evidence(requestEvidence, responseEvidence, observations(result, markerMatch))
    }

    /** Заменяет в теле ответа настоящие значения найденных маркеров их маской, чтобы она не утекла в evidence. */
    private fun maskMarkers(body: String, markerMatch: MarkerMatchResult): String =
        markerMatch.matched.fold(body) { acc, match ->
            if (match.value.isNotEmpty()) acc.replace(match.value, match.masked) else acc
        }

    private fun observations(result: HorizontalCheckResult, markerMatch: MarkerMatchResult): List<Observation> = listOf(
        Observation("ownerBaselineStatus", result.ownerStatus?.toString() ?: "unknown"),
        Observation("anonymousStatus", result.anonymousStatus?.toString() ?: "unknown"),
        Observation("attackerStatus", result.attackerResponse?.status?.toString() ?: "unknown"),
        Observation(
            "markersMatched",
            markerMatch.matched.joinToString(", ") { "${it.path}=${it.masked}" }.ifEmpty { "none" },
        ),
        Observation("markersTotal", markerMatch.total.toString()),
        Observation("repeatConfirmed", result.repeatConfirmed.toString()),
        Observation("denialShapeSimilarity", result.denialSimilarity?.let { "%.2f".format(it) } ?: "unknown"),
    )
}
