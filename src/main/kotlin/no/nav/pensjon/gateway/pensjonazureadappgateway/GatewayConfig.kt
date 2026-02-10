package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.filter.factory.PreserveHostHeaderGatewayFilterFactory
import org.springframework.cloud.gateway.route.RouteLocator
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class GatewayConfig(
    @Value("\${REMOTE}")
    val remote: String,
    val begrunnelseFilter: BegrunnelseFilter,
    val jitFilter: JitFilter
) {

    @Bean
    fun customRouteLocator(builder: RouteLocatorBuilder): RouteLocator {
        return builder.routes()
            .route("internal_selftest") { route ->
                route.path("/psak/internal/selftest")
                    .uri(remote)
            }
            .route("secured_route") { route ->
                route.path("/**")
                    .filters { filterSpec ->
                        filterSpec.filter(PreserveHostHeaderGatewayFilterFactory().apply())
                        filterSpec.filter(begrunnelseFilter)
//                        filterSpec.filter(jitFilter)  //FIXME: Anders
                    }
                    .uri(remote)
            }
            .build()
    }
}
