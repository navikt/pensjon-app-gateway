package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI

@Component
class BegrunnelseFilter : GatewayFilter {

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        val request = exchange.request
        val begrunnelse = request.cookies["tilgang_begrunnelse"]

        return if (begrunnelse.isNullOrEmpty()) {
            // Hvis ingen begrunnelse er oppgitt, omdiriger brukeren til begrunnelse-skjermbildet
            exchange.response.statusCode = HttpStatus.FOUND
            val location = UriComponentsBuilder
                .fromPath("/pensjon-app-gateway/begrunnelse")
                .queryParam("redirect_uri", makeRelativeURI(request.uri))
                .build().toUri()
            exchange.response.headers.location = location
            exchange.response.setComplete()
        } else {
            chain.filter(exchange)
        }
    }

    fun makeRelativeURI(absoluteURI: URI): URI {
        return UriComponentsBuilder.fromUri(absoluteURI)
            .scheme(null)
            .host(null)
            .port(null)
            .build()
            .toUri()
    }
}
