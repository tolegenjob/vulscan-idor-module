package io.vulscan.idor.report

import io.vulscan.kit.contracts.Sensitivity
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class IdorSeverityPolicyTest {
    @Test
    fun `horizontal severity follows resource sensitivity directly`() {
        assertThat(IdorSeverityPolicy.severity(Sensitivity.LOW, VulnType.IDOR_HORIZONTAL, Verdict.LIKELY)).isEqualTo(Severity.LOW)
        assertThat(IdorSeverityPolicy.severity(Sensitivity.MEDIUM, VulnType.IDOR_HORIZONTAL, Verdict.LIKELY)).isEqualTo(Severity.MEDIUM)
        assertThat(IdorSeverityPolicy.severity(Sensitivity.HIGH, VulnType.IDOR_HORIZONTAL, Verdict.LIKELY)).isEqualTo(Severity.HIGH)
    }

    @Test
    fun `suspected is always capped at low, whatever the sensitivity`() {
        assertThat(IdorSeverityPolicy.severity(Sensitivity.HIGH, VulnType.IDOR_VERTICAL, Verdict.SUSPECTED)).isEqualTo(Severity.LOW)
    }

    @Test
    fun `vertical raises one step over a horizontal finding of the same sensitivity`() {
        assertThat(IdorSeverityPolicy.severity(Sensitivity.LOW, VulnType.IDOR_VERTICAL, Verdict.LIKELY)).isEqualTo(Severity.MEDIUM)
        assertThat(IdorSeverityPolicy.severity(Sensitivity.MEDIUM, VulnType.IDOR_VERTICAL, Verdict.LIKELY)).isEqualTo(Severity.HIGH)
    }

    @Test
    fun `critical requires all three conditions at once - high sensitivity, vertical, confirmed`() {
        assertThat(IdorSeverityPolicy.severity(Sensitivity.HIGH, VulnType.IDOR_VERTICAL, Verdict.CONFIRMED)).isEqualTo(Severity.CRITICAL)
    }

    @Test
    fun `vertical plus high sensitivity without confirmed is capped at high, not critical`() {
        assertThat(IdorSeverityPolicy.severity(Sensitivity.HIGH, VulnType.IDOR_VERTICAL, Verdict.LIKELY)).isEqualTo(Severity.HIGH)
    }

    @Test
    fun `confirmed horizontal on high sensitivity stays high - critical needs the vertical bump too`() {
        assertThat(IdorSeverityPolicy.severity(Sensitivity.HIGH, VulnType.IDOR_HORIZONTAL, Verdict.CONFIRMED)).isEqualTo(Severity.HIGH)
    }
}
