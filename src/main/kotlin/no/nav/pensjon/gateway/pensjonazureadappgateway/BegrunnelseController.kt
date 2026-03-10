package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.springframework.context.annotation.Bean
import org.springframework.core.io.ClassPathResource
import org.springframework.http.MediaType
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
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
    fun begrunnelse(model: Model): Mono<String> {
        model.addAttribute("acceptedTerms", JitFilter.ACCEPTED_TERMS)
        return Mono.just("begrunnelse")
    }

    @PostMapping("/pensjon-app-gateway/begrunnelse", consumes = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseBody
    fun submitBegrunnelse(
        @RequestBody request: BegrunnelseRequest,
        exchange: ServerWebExchange
    ): Mono<BegrunnelseResponse> {
        val sanitized = sanitizeForHttpHeader(request.begrunnelse)
        if (sanitized.length < 5) {
            return Mono.just(BegrunnelseResponse(success = false, message = "Begrunnelse må være minst 5 tegn"))
        }
        return exchange.session.map { session ->
            session.attributes[JitFilter.BEGRUNNELSE_SESSION_KEY] = sanitized
            session.attributes[JitFilter.VARIGHET_SESSION_KEY] = request.varighet
            BegrunnelseResponse(success = true, message = "Begrunnelse lagret")
        }
    }

    /**
     * Fjerner tegn som ikke er tillatt i HTTP-headere:
     * linjeskift, kontroll-tegn, og andre ugyldige tegn.
     * Beholder kun bokstaver, tall, mellomrom og vanlige skilletegn.
     */
    private fun sanitizeForHttpHeader(input: String): String {
        return input
            .replace(Regex("[\\r\\n\\t]"), " ")              // Erstatt linjeskift/tab med mellomrom
            .replace(Regex("[^\\w\\sæøåÆØÅ.,;:!\\-?()]"), "") // Fjern alt annet enn tillatte tegn
            .replace(Regex("\\s+"), " ")                       // Fjern doble mellomrom
            .trim()
            .take(200)
    }

    data class BegrunnelseRequest(val begrunnelse: String, val varighet: Int = 1)
    data class BegrunnelseResponse(val success: Boolean, val message: String)
}