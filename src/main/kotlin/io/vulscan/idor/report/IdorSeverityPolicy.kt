package io.vulscan.idor.report

import io.vulscan.kit.contracts.Sensitivity
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType

/** Severity по чувствительности ресурса (I-5 ТЗ): `IDOR_VERTICAL` поднимает на одну ступень, но до `CRITICAL`
 * доходит только при `sensitivity=HIGH` и `verdict=CONFIRMED`; `SUSPECTED` — максимум `LOW` независимо от прочего. */
object IdorSeverityPolicy {
    fun severity(sensitivity: Sensitivity, vulnType: VulnType, verdict: Verdict): Severity {
        if (verdict == Verdict.SUSPECTED) return Severity.LOW

        val base = when (sensitivity) {
            Sensitivity.LOW -> Severity.LOW
            Sensitivity.MEDIUM -> Severity.MEDIUM
            Sensitivity.HIGH -> Severity.HIGH
        }
        val raised = if (vulnType == VulnType.IDOR_VERTICAL) raiseOneStep(base) else base
        val criticalAllowed = sensitivity == Sensitivity.HIGH && verdict == Verdict.CONFIRMED
        return if (raised == Severity.CRITICAL && !criticalAllowed) Severity.HIGH else raised
    }

    private fun raiseOneStep(severity: Severity): Severity {
        val next = severity.ordinal + 1
        return Severity.entries.getOrElse(next) { Severity.CRITICAL }
    }
}
