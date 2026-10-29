package io.vulscan.idor.check

import io.vulscan.idor.identity.IdentityContext
import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.ResourceRef

/**
 * Вертикальная проверка доступа (I-4): видит ли identity с ролью ниже [RoleOrder] функцию, предназначенную
 * для более привилегированной роли. Алгоритм совпадает с горизонтальной проверкой (I-3) — отличается только
 * то, что «владелец»-эталон здесь — это обладатель более высокой роли (`resource.ownerIdentityId`), а не
 * владелец конкретного объекта. Изменяющие (не идемпотентные) функции не вызываются — это гарантирует
 * `IdorJobValidator`/`ScanJobPayloadValidator` для режима `READ_ONLY` ещё на входе задания.
 */
class VerticalAccessCheck(private val horizontal: HorizontalAccessCheck) {
    /**
     * @return `null`, если роль [other] не ниже роли [reference] — проверка в этом случае просто не
     *   выполняется (ни одного запроса не отправляется), а не считается отказом.
     */
    fun check(
        endpoint: EndpointRef,
        resource: ResourceRef,
        rule: AccessRuleRef,
        reference: IdentityContext,
        other: IdentityContext,
    ): HorizontalCheckResult? {
        if (!RoleOrder.isLowerThan(other.role, reference.role)) return null
        return horizontal.check(endpoint, resource, rule, reference, other)
    }
}
