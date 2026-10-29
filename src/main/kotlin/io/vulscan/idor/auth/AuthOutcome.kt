package io.vulscan.idor.auth

/** Результат попытки аутентификации или проверки сессии одной идентичности. */
sealed interface AuthOutcome {
    data object Success : AuthOutcome
    data class Failed(val reason: String) : AuthOutcome
}
