package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.slf4j.Logger
import org.slf4j.LoggerFactory.getLogger
import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.http.MediaType
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.time.LocalDateTime

@Component
class JitFilter(
    @param:Value("\${PENSJON-JIT-FOR-Q_URL}") private val jitApiUrl: String,
    @param:Value("\${PENSJON-JIT-FOR-Q_SCOPE}") private val jitApiScope: String,
    @param:Value("\${NAIS_TOKEN_EXCHANGE_ENDPOINT}") private val tokenExchangeEndpoint: String,
    private val webClient: WebClient,
    private val authorizedClientRepository: ServerOAuth2AuthorizedClientRepository
) : GatewayFilter {

    private val logger: Logger = getLogger(javaClass)

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        logger.info("Calling JIT API at {}", jitApiUrl)

        return ReactiveSecurityContextHolder.getContext()
            .mapNotNull { it.authentication }
            .filter { it is OAuth2AuthenticationToken }
            .cast(OAuth2AuthenticationToken::class.java)
            .flatMap { authentication ->
                authorizedClientRepository.loadAuthorizedClient<OAuth2AuthorizedClient>(
                    authentication.authorizedClientRegistrationId,
                    authentication,
                    exchange
                )
            }
            .map { authorizedClient -> authorizedClient.accessToken.tokenValue }
            .flatMap { accessToken ->
                exchangeToken(accessToken)
            }
            .flatMap { oboToken ->
                hasActiveJit(oboToken)
                    .flatMap { isActive ->
                        if (isActive) {
                            logger.info("Active JIT already exists, skipping setJit API call")
                            Mono.empty()
                        } else {
                            logger.info("No active JIT, calling setJit API")
                            setJit(oboToken)
                        }
                    }
            }
            .then(chain.filter(exchange))
            .onErrorResume { error ->
                logger.error("Error during JIT API call, proceeding with request anyway: {}", error.message)
                chain.filter(exchange)
            }
    }

    private fun exchangeToken(userToken: String): Mono<String> {
        logger.info("Exchanging token for JIT API access")

        val requestBody = mapOf(
            "identity_provider" to "entra_id",
            "target" to jitApiScope,
            "user_token" to userToken
        )

        return webClient.post()
            .uri(tokenExchangeEndpoint)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestBody)
            .retrieve()
            .bodyToMono<TokenResponse>()
            .map { it.access_token }
            .doOnSuccess { logger.info("Token exchange successful") }
            .doOnError { error -> logger.error("Token exchange failed: {}", error.message) }
    }

    private fun setJit(accessToken: String): Mono<Void> {
        return webClient.post()
            .uri("$jitApiUrl/api/jit")
            .header("Authorization", "Bearer $accessToken")
            .bodyValue(
                mapOf(
                    "environment" to "Q2",
                    "startTime" to LocalDateTime.now().toString(),
                    "durationInHours" to "1",
                    "reason" to "Tester lagring JIT-opplysninger for pensjon-app-gateway",
                    "acceptedTerms" to "Jeg aksepterer at mine oppslag på personlige opplysninger blir loggført"
                )
            )
            .retrieve()
            .toBodilessEntity()
            .doOnSuccess { response ->
                logger.info("JIT API call successful, status: {}", response?.statusCode)
            }
            .doOnError { error ->
                logger.error("JIT API call failed: {}", error.message)
            }
            .then()
    }

    private fun hasActiveJit(accessToken: String): Mono<Boolean> {
        return webClient.get()
            .uri("$jitApiUrl/api/jit/active")
            .header("Authorization", "Bearer $accessToken")
            .retrieve()
            .bodyToMono<Boolean>()
            .doOnSuccess { active ->
                logger.info("Checked active JIT status: {}", active)
            }
            .doOnError { error ->
                logger.error("Failed to check active JIT status: {}", error.message)
            }
    }

    data class TokenResponse(
        val access_token: String,
        val token_type: String,
        val expires_in: Int
    )
}
