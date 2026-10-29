package io.vulscan.idor.json

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JsonPathTest {
    private val body = """{"username":"alice","ownerEmail":"alice@lab.test","items":[{"sku":"A1"},{"sku":"B2"}],"nested":{"flag":true,"count":3}}"""

    @Test
    fun `simple and nested fields`() {
        assertThat(JsonPath.readString(body, "$.username")).isEqualTo("alice")
        assertThat(JsonPath.readString(body, "$.nested.flag")).isEqualTo("true")
        assertThat(JsonPath.readString(body, "$.nested.count")).isEqualTo("3")
    }

    @Test
    fun `array index`() {
        assertThat(JsonPath.readString(body, "$.items[0].sku")).isEqualTo("A1")
        assertThat(JsonPath.readString(body, "$.items[1].sku")).isEqualTo("B2")
    }

    @Test
    fun `missing path, object path and invalid json are all null`() {
        assertThat(JsonPath.readString(body, "$.missing")).isNull()
        assertThat(JsonPath.readString(body, "$.nested")).isNull()
        assertThat(JsonPath.readString(body, "$.items[9].sku")).isNull()
        assertThat(JsonPath.readString("not json", "$.username")).isNull()
        assertThat(JsonPath.exists(body, "$.username")).isTrue()
        assertThat(JsonPath.exists(body, "$.missing")).isFalse()
    }
}
