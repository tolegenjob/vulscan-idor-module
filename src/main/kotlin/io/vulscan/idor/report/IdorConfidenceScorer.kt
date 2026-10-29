package io.vulscan.idor.report

import io.vulscan.kit.contracts.Verdict

/** Confidence по вердикту (I-5 ТЗ): базовое значение минус штрафы, clamp 1..99. */
object IdorConfidenceScorer {
    fun score(verdict: Verdict, markerRatio: Double, denialShapeAvailable: Boolean = true): Int {
        var value = when (verdict) {
            Verdict.CONFIRMED -> 95
            Verdict.LIKELY -> 75
            Verdict.SUSPECTED -> 35
        }
        if (markerRatio < 1.0) value -= 10
        if (!denialShapeAvailable) value -= 15
        return value.coerceIn(1, 99)
    }
}
