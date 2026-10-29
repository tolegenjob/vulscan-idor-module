package io.vulscan.idor.check

import io.vulscan.idor.compare.ResponseSignature
import io.vulscan.idor.compare.Similarity
import io.vulscan.kit.net.ProbeResponse

/**
 * Классифицирует ответ атакующей identity на запрос к чужому ресурсу (I-3 ТЗ, шаг "проба").
 * Не решает, истекла ли сессия — это уже сделал [io.vulscan.idor.auth.SessionManager] до вызова.
 */
object ResponseClassifier {
    fun classify(
        response: ProbeResponse,
        ownerSignature: ResponseSignature,
        denialSignature: ResponseSignature,
        markerMatch: MarkerMatchResult,
        loginUrl: String?,
        similarityThreshold: Double,
    ): AccessOutcome {
        if (response.status == 401 || response.status == 403) return AccessOutcome.DENIED
        if (response.status == 404 || response.status == 410) return AccessOutcome.DENIED_HIDDEN
        if (response.status in 300..399) {
            val location = response.headers.entries.firstOrNull { it.key.equals("location", true) }?.value
            if (loginUrl == null || (location != null && location.contains(loginUrl))) return AccessOutcome.AUTH_REQUIRED
        }
        if (response.status in 500..599) return AccessOutcome.ERROR
        if (response.status !in 200..299) return AccessOutcome.AMBIGUOUS

        if (markerMatch.any) return AccessOutcome.UNAUTHORIZED_ACCESS

        val signature = ResponseSignature.of(response)
        if (Similarity.of(signature, denialSignature) >= similarityThreshold) return AccessOutcome.DENIED_SOFT
        if (Similarity.sameStructure(signature, ownerSignature) && !Similarity.sameStructure(signature, denialSignature)) {
            return AccessOutcome.AMBIGUOUS_STRUCTURE
        }
        return AccessOutcome.AMBIGUOUS
    }
}
