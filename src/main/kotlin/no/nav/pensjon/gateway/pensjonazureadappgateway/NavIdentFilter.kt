package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.core.Ordered
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono


@Component
class NavIdentFilter : GlobalFilter, Ordered {

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        return fetchNAVident()
            .doOnSuccess {navIdent ->
                exchange.request.mutate().headers { it.add("x-forwarded-navident", navIdent) }
            }
            .then(chain.filter(exchange))
    }

    override fun getOrder(): Int {
        return -1
    }

    private fun fetchNAVident(): Mono<String> {
        return ReactiveSecurityContextHolder.getContext()
            .map { (it.authentication?.principal as? OidcUser)?.getClaimAsString("NAVident") ?: "" }
    }
}