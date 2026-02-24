package no.nav.pensjon.gateway.pensjonazureadappgateway

import org.slf4j.Logger
import org.slf4j.LoggerFactory.getLogger
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.web.reactive.function.client.*
import reactor.netty.http.client.HttpClient

@Configuration
@EnableWebFluxSecurity
class SecurityConfiguration {
    private val logger: Logger = getLogger(javaClass)

    @Bean
    fun springSecurityFilterChain(
        http: ServerHttpSecurity,
        reactiveAuthenticationManager: ReactiveAuthenticationManager,
        clientRegistrationRepository: ReactiveClientRegistrationRepository,
    ): SecurityWebFilterChain {
        http.csrf { it.disable() }
        http.authorizeExchange { authorize: ServerHttpSecurity.AuthorizeExchangeSpec ->
            authorize
                .pathMatchers("/psak/internal/selftest").permitAll()
                .pathMatchers("/actuator/health/**").permitAll()
                .pathMatchers("/actuator/prometheus/**").permitAll()
                .anyExchange().authenticated()
        }

        val authorizationRequestResolver = DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository)
        authorizationRequestResolver.setAuthorizationRequestCustomizer { builder ->
            builder.additionalParameters { params -> params["domain_hint"] = "nav.no" }
        }

        http.oauth2Login {
            it.authenticationManager(reactiveAuthenticationManager)
            it.authorizationRequestResolver(authorizationRequestResolver)
        }
        http.oauth2Client { it.authenticationManager(reactiveAuthenticationManager) }
        return http.build()
    }

    @Bean
    fun authenticationManager(
        client: ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>,
        oidcUserService: ReactiveOAuth2UserService<OidcUserRequest, OidcUser>,
        oauth2UserService: ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User>,
    ): ReactiveAuthenticationManager = DelegatingReactiveAuthenticationManager(
        OidcAuthorizationCodeReactiveAuthenticationManager(
            client, oidcUserService
        ).also { it.setJwtDecoderFactory(ReactiveOidcIdTokenDecoderFactory().apply { setWebClientResolver { webClientProxy() } }) }, OAuth2LoginReactiveAuthenticationManager(
            client, oauth2UserService
        )
    )

    @Bean
    fun webClientReactiveAuthorizationCodeTokenResponseClient(): WebClientReactiveAuthorizationCodeTokenResponseClient =
        WebClientReactiveAuthorizationCodeTokenResponseClient().apply {
            setWebClient(webClientProxy())
        }

    @Bean
    fun oidcReactiveOAuth2UserService(reactiveOAuth2UserService: ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User>): OidcReactiveOAuth2UserService =
        OidcReactiveOAuth2UserService().apply {
            setOauth2UserService(
                reactiveOAuth2UserService
            )
        }

    @Bean
    fun reactiveOAuth2UserService(): DefaultReactiveOAuth2UserService {
        return DefaultReactiveOAuth2UserService().apply {
            setWebClient(webClientProxy())
        }
    }

    @Bean
    fun webClient(): WebClient = webClientProxy()


    @Bean
    fun reactiveJwtDecoder(
        @Value("\${AZURE_APP_CLIENT_ID}") clientId: String,
        @Value("\${AZURE_OPENID_CONFIG_ISSUER}") issuer: String,
        @Value("\${AZURE_OPENID_CONFIG_JWKS_URI}") jwkSetUri: String,
    ): ReactiveJwtDecoder {
        val jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).webClient(webClientProxy()).build()

        jwtDecoder.setJwtValidator(
            DelegatingOAuth2TokenValidator(
                JwtTimestampValidator(),
                JwtIssuerValidator(issuer),
                JwtClaimValidator<Collection<String>>("aud") { clientId in it },
            )
        )
        return jwtDecoder
    }

    fun webClientProxy(): WebClient =
        WebClient.builder().clientConnector(
            ReactorClientHttpConnector(
                HttpClient.create().proxyWithSystemProperties()
            )
        ).filter { request, next ->
            logger.info("Request to {}", request.url())
            next.exchange(request)
        }.build()
}
