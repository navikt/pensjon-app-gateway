package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.springframework.context.annotation.Bean
import org.springframework.core.io.ClassPathResource
import org.springframework.http.MediaType
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.reactive.function.server.RouterFunctions
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Controller
class BegrunnelseController {
    @Bean
    fun assetsRouter() =
        RouterFunctions
            .resources("/pensjon-app-gateway/public/" + "**", ClassPathResource("public/"))

    @GetMapping("/pensjon-app-gateway/begrunnelse")
    fun otp(): Mono<String> {
        return Mono.just("begrunnelse")
    }

    @PostMapping("/pensjon-app-gateway/begrunnelse", consumes = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseBody
    fun submitBegrunnelse(
        @RequestBody request: BegrunnelseRequest,
        exchange: ServerWebExchange
    ): Mono<BegrunnelseResponse> {
        return exchange.session.map { session ->
            session.attributes[JitFilter.BEGRUNNELSE_SESSION_KEY] = request.begrunnelse
            session.attributes[JitFilter.VARIGHET_SESSION_KEY] = request.varighet
            BegrunnelseResponse(success = true, message = "Begrunnelse lagret")
        }
    }

    data class BegrunnelseRequest(val begrunnelse: String, val varighet: Int = 1)
    data class BegrunnelseResponse(val success: Boolean, val message: String)
}