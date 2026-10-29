package io.vulscan.idor.check

import io.vulscan.idor.json.JsonPath

/** Одно совпадение маркера владельца в ответе другой идентичности. [masked] — значение для evidence, без PII. */
data class MarkerMatch(val path: String, val masked: String)

data class MarkerMatchResult(val matched: List<MarkerMatch>, val total: Int) {
    /** Доля найденных маркеров: 0.0, если маркеров нет вовсе (оракул недоступен — см. I-1 markersMissing). */
    val ratio: Double get() = if (total == 0) 0.0 else matched.size.toDouble() / total
    val all: Boolean get() = total > 0 && matched.size == total
    val any: Boolean get() = matched.isNotEmpty()
}

/**
 * Оракул «тот же объект»: значение владельца по каждому JSONPath из `ownerMarkers` ищется в ответе другой
 * идентичности по тому же пути. Совпадение по значению, а не просто присутствие пути.
 */
object OwnerMarkerMatcher {
    fun match(ownerMarkers: List<String>, ownerBody: String, candidateBody: String): MarkerMatchResult {
        val matched = ownerMarkers.mapNotNull { path ->
            val ownerValue = JsonPath.readString(ownerBody, path) ?: return@mapNotNull null
            val candidateValue = JsonPath.readString(candidateBody, path)
            if (candidateValue == ownerValue) MarkerMatch(path, mask(ownerValue)) else null
        }
        return MarkerMatchResult(matched, ownerMarkers.size)
    }

    /** `alice@lab.test` → `al***@lab.test`; прочее — первый и последний символ, остальное звёздами. */
    fun mask(value: String): String {
        if (value.isEmpty()) return value
        val at = value.indexOf('@')
        if (at > 0) return value.take(minOf(2, at)) + "***" + value.substring(at)
        if (value.length <= 2) return "*".repeat(value.length)
        return value.first() + "*".repeat(value.length - 2) + value.last()
    }
}
