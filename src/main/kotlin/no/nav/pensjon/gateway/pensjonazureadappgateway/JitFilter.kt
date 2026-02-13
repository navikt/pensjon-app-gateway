package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.slf4j.Logger
import org.slf4j.LoggerFactory.getLogger
import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI
import java.time.LocalDateTime

@Component
class JitFilter(
    @param:Value("\${PENSJON-JIT-FOR-Q_URL}") private val jitApiUrl: String,
    @param:Value("\${PENSJON-JIT-FOR-Q_SCOPE}") private val jitApiScope: String,
    @param:Value("\${NAIS_TOKEN_EXCHANGE_ENDPOINT}") private val tokenExchangeEndpoint: String,
    @param:Value("\${ENVIRONMENT_NAME}") private val environmentName: String,
    private val webClient: WebClient,
    private val authorizedClientRepository: ServerOAuth2AuthorizedClientRepository
) : GatewayFilter {

    private val logger: Logger = getLogger(javaClass)

    companion object {
        const val BEGRUNNELSE_SESSION_KEY = "tilgang_begrunnelse"
        const val VARIGHET_SESSION_KEY = "tilgang_varighet"
    }

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        logger.info("JitFilter: Checking JIT access for {}", exchange.request.uri)

        return exchange.session.flatMap { session ->
            getOboToken(exchange).flatMap { oboToken ->
                hasActiveJit(oboToken).flatMap { isActive ->
                    if (isActive) {
                        // Bruker har aktiv JIT, slipp gjennom
                        logger.info("User has active JIT access, proceeding")
                        chain.filter(exchange)
                    } else {
                        // Bruker har ikke aktiv JIT, sjekk om begrunnelse er oppgitt
                        val begrunnelse = session.getAttribute<String>(BEGRUNNELSE_SESSION_KEY)

                        if (begrunnelse.isNullOrEmpty()) {
                            // Ingen begrunnelse, redirect til skjema
                            logger.info("No active JIT and no begrunnelse, redirecting to form")
                            redirectToBegrunnelseForm(exchange)
                        } else {
                            // Begrunnelse finnes, opprett JIT tilgang
                            logger.info("No active JIT but begrunnelse found, creating JIT access")
                            val varighet = session.getAttribute<Int>(VARIGHET_SESSION_KEY) ?: 1
                            setJit(oboToken, begrunnelse, varighet)
                                .doOnSuccess {
                                    // Fjern begrunnelse og varighet fra session etter bruk
                                    session.attributes.remove(BEGRUNNELSE_SESSION_KEY)
                                    session.attributes.remove(VARIGHET_SESSION_KEY)
                                }
                                .then(chain.filter(exchange))
                        }
                    }
                }
            }
        }.onErrorResume { error ->
            logger.error("Error during JIT check, proceeding with request anyway: {}", error.message)
            chain.filter(exchange)
        }
    }

    private fun redirectToBegrunnelseForm(exchange: ServerWebExchange): Mono<Void> {
        exchange.response.statusCode = HttpStatus.FOUND
        val location = UriComponentsBuilder
            .fromPath("/pensjon-app-gateway/begrunnelse")
            .queryParam("redirect_uri", makeRelativeURI(exchange.request.uri))
            .build().toUri()
        exchange.response.headers.location = location
        return exchange.response.setComplete()
    }

    private fun makeRelativeURI(absoluteURI: URI): URI {
        return UriComponentsBuilder.fromUri(absoluteURI)
            .scheme(null)
            .host(null)
            .port(null)
            .build()
            .toUri()
    }

    private fun getOboToken(exchange: ServerWebExchange): Mono<String> {
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
            .flatMap { accessToken -> exchangeToken(accessToken) }
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

    private fun setJit(accessToken: String, begrunnelse: String, varighet: Int): Mono<Void> {
        logger.info("Creating JIT access with begrunnelse, duration: {} hours", varighet)
        return webClient.post()
            .uri("$jitApiUrl/api/jit")
            .header("Authorization", "Bearer $accessToken")
            .bodyValue(
                mapOf(
                    "environment" to environmentName,
                    "startTime" to LocalDateTime.now().toString(),
                    "durationInHours" to varighet.toString(),
                    "reason" to begrunnelse,
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
            .defaultIfEmpty(false)
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
