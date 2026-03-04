package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono


@Component
class NavIdentFilter : GatewayFilter {

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        return fetchNAVident()
            .flatMap { navIdent ->
                if (navIdent.isNotBlank()) {
                    val mutatedRequest = exchange.request.mutate()
                        .header("x-forwarded-navident", navIdent)
                        .build()
                    val mutatedExchange = exchange.mutate().request(mutatedRequest).build()
                    chain.filter(mutatedExchange)
                } else {
                    chain.filter(exchange)
                }
            }
           // .switchIfEmpty(chain.filter(exchange))
    }


    private fun fetchNAVident(): Mono<String> {
        return ReactiveSecurityContextHolder.getContext()
            .map { (it.authentication?.principal as? OidcUser)?.getClaimAsString("NAVident") ?: "" }
    }
}