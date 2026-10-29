package io.vulscan.idor.check

/**
 * Частичный порядок ролей для вертикальных проверок (I-4): `USER < ADMIN`. Роль, не входящая в известный
 * список, несравнима ни с чем — для неё вертикальная проверка просто не выполняется (а не считается ниже/выше).
 */
object RoleOrder {
    private val known = listOf("ANONYMOUS", "USER", "MODERATOR", "ADMIN")

    /** true, только если обе роли известны и [role] строго ниже [reference] в этом порядке. */
    fun isLowerThan(role: String, reference: String): Boolean {
        val a = known.indexOf(role.uppercase())
        val b = known.indexOf(reference.uppercase())
        return a >= 0 && b >= 0 && a < b
    }
}
