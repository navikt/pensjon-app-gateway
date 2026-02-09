package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.slf4j.Logger
import org.slf4j.LoggerFactory.getLogger
import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.http.MediaType
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.time.LocalDateTime

@Component
class JitFilter(
    @Value("\${PENSJON-JIT-FOR-Q_URL}") private val jitApiUrl: String,
    @Value("\${PENSJON-JIT-FOR-Q_SCOPE}") private val jitApiScope: String,
    @Value("\${NAIS_TOKEN_EXCHANGE_ENDPOINT}") private val tokenExchangeEndpoint: String,
    private val webClient: WebClient
) : GatewayFilter {

    private val logger: Logger = getLogger(javaClass)

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        logger.info("Calling JIT API at {}", jitApiUrl)

        return ReactiveSecurityContextHolder.getContext()
            .flatMap { securityContext ->
                val authentication = securityContext.authentication
                if (authentication is OAuth2AuthenticationToken && authentication.principal is OidcUser) {
                    val oidcUser = authentication.principal as OidcUser
                    val userToken = oidcUser.idToken.tokenValue
                    exchangeToken(userToken)
                } else {
                    Mono.error(IllegalStateException("No valid OIDC user token found"))
                }
            }
            .flatMap { accessToken ->
                callJitApi(accessToken)
            }
            .then(chain.filter(exchange))
            .onErrorResume { error ->
                logger.error("Error during JIT API call, proceeding with request anyway: {}", error.message)
                chain.filter(exchange)
            }
    }

    private fun exchangeToken(userToken: String): Mono<String> {
        logger.info("Exchanging token for JIT API access")

        val formData = LinkedMultiValueMap<String, String>().apply {
            add("identity_provider", "entra_id")
            add("target", jitApiScope)
            add("user_token", userToken)
        }

        return webClient.post()
            .uri(tokenExchangeEndpoint)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData(formData))
            .retrieve()
            .bodyToMono(TokenResponse::class.java)
            .map { it.access_token }
            .doOnSuccess { logger.info("Token exchange successful") }
            .doOnError { error -> logger.error("Token exchange failed: {}", error.message) }
    }

    private fun callJitApi(accessToken: String): Mono<Void> {
        return webClient.post()
            .uri("$jitApiUrl/api/jit")
            .header("Authorization", "Bearer $accessToken")
            .bodyValue(
                mapOf(
                    "environment" to "dev",
                    "startTime" to LocalDateTime.now().toString(),
                    "durationInHours" to "2",
                    "reason" to "Tester lagring JIT-opplysninger for pensjon-app-gateway",
                    "acceptedTerms" to "Jeg aksepterer at mine oppslag på personlige opplysninger blir loggført"
                )
            )
            .retrieve()
            .toBodilessEntity()
            .doOnSuccess { response ->
                logger.info("JIT API call successful, status: {}", response.statusCode)
            }
            .doOnError { error ->
                logger.error("JIT API call failed: {}", error.message)
            }
            .then()
    }

    data class TokenResponse(
        val access_token: String,
        val token_type: String,
        val expires_in: Int
    )
}
