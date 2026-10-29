package io.vulscan.idor.check

import io.vulscan.idor.compare.ResponseSignature
import io.vulscan.kit.net.ProbeResponse

/** «Форма отказа» для ресурса: как выглядит ответ атакующей identity на гарантированно несуществующий id. */
data class DenialShape(val status: Int, val signature: ResponseSignature) {
    companion object {
        fun of(response: ProbeResponse): DenialShape = DenialShape(response.status, ResponseSignature.of(response))
    }
}
