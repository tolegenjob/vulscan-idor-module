package io.vulscan.idor.report

import io.vulscan.kit.contracts.Verdict
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class IdorConfidenceScorerTest {
    @Test
    fun `base scores match the spec for each verdict`() {
        assertThat(IdorConfidenceScorer.score(Verdict.CONFIRMED, markerRatio = 1.0)).isEqualTo(95)
        assertThat(IdorConfidenceScorer.score(Verdict.LIKELY, markerRatio = 1.0)).isEqualTo(75)
        assertThat(IdorConfidenceScorer.score(Verdict.SUSPECTED, markerRatio = 1.0)).isEqualTo(35)
    }

    @Test
    fun `an incomplete marker ratio costs 10 points`() {
        assertThat(IdorConfidenceScorer.score(Verdict.CONFIRMED, markerRatio = 0.5)).isEqualTo(85)
    }

    @Test
    fun `a missing denial shape costs 15 points`() {
        assertThat(IdorConfidenceScorer.score(Verdict.LIKELY, markerRatio = 1.0, denialShapeAvailable = false)).isEqualTo(60)
    }

    @Test
    fun `both penalties stack`() {
        assertThat(IdorConfidenceScorer.score(Verdict.SUSPECTED, markerRatio = 0.5, denialShapeAvailable = false)).isEqualTo(10)
    }

    @Test
    fun `the result is always clamped to 1 to 99`() {
        assertThat(IdorConfidenceScorer.score(Verdict.SUSPECTED, markerRatio = 0.0, denialShapeAvailable = false)).isGreaterThanOrEqualTo(1)
    }
}
