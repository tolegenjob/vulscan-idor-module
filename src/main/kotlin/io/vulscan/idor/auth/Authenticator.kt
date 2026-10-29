package io.vulscan.idor.auth

import io.vulscan.kit.worker.BudgetedHttp
import io.vulscan.idor.identity.IdentityContext

/** Устанавливает сессию одной идентичности. Пароли/токены никогда не попадают в сообщения исключений или логов. */
interface Authenticator {
    fun authenticate(identity: IdentityContext, http: BudgetedHttp): AuthOutcome
}
