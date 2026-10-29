package io.vulscan.idor.check

/** Отличает числовой идентификатор от строкового — определяет, как строится гарантированно несуществующее значение. */
object IdValueKind {
    private val NUMBER = Regex("^-?(0|[1-9]\\d*)$")

    fun isNumeric(idValue: String): Boolean = NUMBER.matches(idValue)
}
