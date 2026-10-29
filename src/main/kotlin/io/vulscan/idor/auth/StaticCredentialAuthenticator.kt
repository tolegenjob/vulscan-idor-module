package io.vulscan.idor.auth

import io.vulscan.kit.worker.BudgetedHttp
import io.vulscan.idor.identity.IdentityContext

/** BEARER_STATIC/COOKIE_STATIC/HEADER_STATIC: заголовок/cookie уже установлены при создании [IdentityContext]. */
object StaticCredentialAuthenticator : Authenticator {
    override fun authenticate(identity: IdentityContext, http: BudgetedHttp): AuthOutcome = AuthOutcome.Success
}
