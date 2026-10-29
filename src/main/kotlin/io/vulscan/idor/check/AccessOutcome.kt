package io.vulscan.idor.check

/** Итог классификации одной пробы атакующей identity по ресурсу (см. I-3 ТЗ). */
enum class AccessOutcome {
    /** Атакующему действительно разрешён доступ — ожидаемо (`expected=ALLOW`/`PUBLIC`), finding не создаётся. */
    ALLOWED_AS_EXPECTED,

    /** Ресурс отдаёт данные анонимно — проверки для DENY для него не создают finding. */
    PUBLIC_OBSERVED,

    DENIED,
    DENIED_HIDDEN,
    DENIED_SOFT,
    AUTH_REQUIRED,
    ERROR,
    UNAUTHORIZED_ACCESS,
    AMBIGUOUS_STRUCTURE,
    AMBIGUOUS,
}
