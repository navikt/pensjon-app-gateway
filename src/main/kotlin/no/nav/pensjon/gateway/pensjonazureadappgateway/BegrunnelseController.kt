package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.springframework.context.annotation.Bean
import org.springframework.core.io.ClassPathResource
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.reactive.function.server.RouterFunctions
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
}