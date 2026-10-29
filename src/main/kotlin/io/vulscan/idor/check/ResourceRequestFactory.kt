package io.vulscan.idor.check

import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.ParameterId
import io.vulscan.kit.net.ProbeRequest
import okhttp3.HttpUrl.Companion.toHttpUrl

/** Строит запрос к ресурсу: подставляет [idValue] в [idParameter] (единственный переменный параметр ресурса). */
object ResourceRequestFactory {
    private const val ACCEPT = "application/json,text/html;q=0.9,*/*;q=0.8"

    fun build(endpoint: EndpointRef, idParameter: ParameterId, idValue: String): ProbeRequest {
        val url = when (idParameter.location) {
            ParamLocation.PATH -> endpoint.url.replace("{${idParameter.name}}", pathEncode(idValue))
            ParamLocation.QUERY -> endpoint.url.toHttpUrl().newBuilder().setQueryParameter(idParameter.name, idValue).build().toString()
            else -> error("Unsupported idParameter location ${idParameter.location}")
        }
        return ProbeRequest(endpoint.method, url, mapOf("Accept" to ACCEPT))
    }

    /** Без заголовков аутентификации — для анонимного контроля. */
    fun anonymous(endpoint: EndpointRef, idParameter: ParameterId, idValue: String): ProbeRequest = build(endpoint, idParameter, idValue)

    /** Значение, гарантированно отсутствующее: `2^31-1` для числовых идентификаторов, иначе исходное значение + маркер. */
    fun nonexistentValue(idValue: String, canary: String): String =
        if (IdValueKind.isNumeric(idValue)) "2147483647" else "$idValue-nonexistent-$canary"

    private fun pathEncode(text: String): String = buildString {
        for (b in text.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt().toChar()
            if (b >= 0 && (c.isLetterOrDigit() && c.code < 128 || c in "-._~")) append(c) else append('%').append("%02X".format(b.toInt() and 0xff))
        }
    }
}
