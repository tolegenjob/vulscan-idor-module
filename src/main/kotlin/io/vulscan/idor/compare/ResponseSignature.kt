package io.vulscan.idor.compare

import io.vulscan.kit.net.ProbeResponse

/** Компактное представление ответа для структурного сравнения: статус, длина, слова и множество JSON-ключей/HTML-тегов. */
class ResponseSignature(val status: Int, val length: Int, val tokens: Set<String>, val keys: Set<String>) {
    companion object {
        private val WORD = Regex("""[\p{L}\p{N}_]{3,}""")
        private val JSON_KEY = Regex(""""([^"]+)"\s*:""")
        private val TAG = Regex("""<([a-zA-Z][a-zA-Z0-9-]*)""")

        fun of(response: ProbeResponse): ResponseSignature {
            val body = response.bodyText()
            val isJson = response.headers.entries.firstOrNull { it.key.equals("content-type", true) }
                ?.value?.contains("json", ignoreCase = true) == true
            val keys = if (isJson) JSON_KEY.findAll(body).map { it.groupValues[1] }.toSet() else TAG.findAll(body).map { it.groupValues[1].lowercase() }.toSet()
            val tokens = WORD.findAll(body).map { it.value.lowercase() }.toSet()
            return ResponseSignature(response.status, body.length, tokens, keys)
        }
    }
}

object Similarity {
    /** 0.5·Jaccard(слова) + 0.5·Jaccard(ключи/теги) — для оценки похожести на «форму отказа». */
    fun of(a: ResponseSignature, b: ResponseSignature): Double = 0.5 * jaccard(a.tokens, b.tokens) + 0.5 * jaccard(a.keys, b.keys)

    /** Одинаковый непустой набор ключей/тегов — признак «та же форма ответа», независимо от конкретных значений. */
    fun sameStructure(a: ResponseSignature, b: ResponseSignature): Boolean = a.keys.isNotEmpty() && a.keys == b.keys

    private fun jaccard(a: Set<String>, b: Set<String>): Double {
        if (a.isEmpty() && b.isEmpty()) return 1.0
        val union = a.size + b.size - a.intersect(b).size
        return if (union == 0) 1.0 else a.intersect(b).size.toDouble() / union
    }
}
