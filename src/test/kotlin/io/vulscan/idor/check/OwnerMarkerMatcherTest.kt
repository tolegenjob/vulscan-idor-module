package io.vulscan.idor.check

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class OwnerMarkerMatcherTest {
    private val ownerBody = """{"id":1,"ownerEmail":"alice@lab.test","token":"s3cr3t12"}"""

    @Test
    fun `value found at the same path in the candidate counts as matched`() {
        val candidate = """{"id":1,"ownerEmail":"alice@lab.test"}"""
        val result = OwnerMarkerMatcher.match(listOf("$.ownerEmail"), ownerBody, candidate)
        assertThat(result.matched).hasSize(1)
        assertThat(result.all).isTrue()
        assertThat(result.any).isTrue()
    }

    @Test
    fun `a different value at the same path does not match`() {
        val candidate = """{"id":2,"ownerEmail":"bob@lab.test"}"""
        val result = OwnerMarkerMatcher.match(listOf("$.ownerEmail"), ownerBody, candidate)
        assertThat(result.matched).isEmpty()
        assertThat(result.any).isFalse()
    }

    @Test
    fun `a missing path in the candidate does not match`() {
        val candidate = """{"id":2}"""
        val result = OwnerMarkerMatcher.match(listOf("$.ownerEmail"), ownerBody, candidate)
        assertThat(result.matched).isEmpty()
    }

    @Test
    fun `partial match reports the ratio and keeps the total`() {
        val candidate = """{"ownerEmail":"alice@lab.test"}"""
        val result = OwnerMarkerMatcher.match(listOf("$.ownerEmail", "$.token"), ownerBody, candidate)
        assertThat(result.matched).hasSize(1)
        assertThat(result.total).isEqualTo(2)
        assertThat(result.ratio).isEqualTo(0.5)
        assertThat(result.all).isFalse()
    }

    @Test
    fun `no owner markers configured means nothing can ever match`() {
        val result = OwnerMarkerMatcher.match(emptyList(), ownerBody, ownerBody)
        assertThat(result.total).isEqualTo(0)
        assertThat(result.ratio).isEqualTo(0.0)
        assertThat(result.any).isFalse()
        assertThat(result.all).isFalse()
    }

    @Test
    fun `email values are masked keeping only the first two characters and the domain`() {
        assertThat(OwnerMarkerMatcher.mask("alice@lab.test")).isEqualTo("al***@lab.test")
    }

    @Test
    fun `a short email local part is masked without overrunning it`() {
        assertThat(OwnerMarkerMatcher.mask("al@lab.test")).isEqualTo("al***@lab.test")
    }

    @Test
    fun `plain values keep only their first and last character`() {
        val masked = OwnerMarkerMatcher.mask("s3cr3t12")
        assertThat(masked).startsWith("s").endsWith("2").doesNotContain("3cr3t1")
        assertThat(masked).hasSize("s3cr3t12".length)
    }

    @Test
    fun `very short plain values are fully masked`() {
        assertThat(OwnerMarkerMatcher.mask("ab")).isEqualTo("**")
    }
}
