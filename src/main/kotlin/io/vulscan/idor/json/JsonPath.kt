package io.vulscan.idor.json

import io.vulscan.kit.contracts.Json
import tools.jackson.databind.JsonNode

/**
 * Минимальный JSONPath, достаточный для задания: `$.field`, `$.a.b`, `$.items[0].sku`.
 * Фильтры и срезы не поддерживаются — такой запрос всегда не находит значения.
 */
object JsonPath {
    private val TOKEN = Regex("""\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)]""")

    private fun navigate(root: JsonNode, path: String): JsonNode? {
        if (!path.startsWith("$")) return null
        var node: JsonNode? = root
        for (m in TOKEN.findAll(path.removePrefix("$"))) {
            val current = node ?: return null
            node = m.groups[1]?.value?.let { current.get(it) } ?: m.groups[2]?.value?.toInt()?.let { current.get(it) }
        }
        return node
    }

    /** Текстовое представление значения (строка/число/булево) или null, если путь не найден либо ведёт в объект/массив. */
    fun readString(body: String, path: String): String? {
        val root = try {
            Json.mapper.readTree(body)
        } catch (e: Exception) {
            return null
        }
        val node = navigate(root, path) ?: return null
        return if (node.isValueNode) node.asString() else null
    }

    fun exists(body: String, path: String): Boolean = readString(body, path) != null
}
