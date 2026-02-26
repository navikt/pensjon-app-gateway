# pensjon-app-gateway

En Spring Cloud Gateway-applikasjon som fungerer som en sikker revers-proxy foran NAV sine pensjonsapplikasjoner (f.eks. PSAK).

## Funksjonalitet

- **Innlogging via Entra ID (Azure AD):** Alle forespørsler krever autentisering med OAuth2/OIDC via Entra ID.
- **Just-In-Time (JIT) tilgangskontroll:** Før trafikk slippes gjennom til backend, sjekkes det om brukeren har en aktiv JIT-tilgang. Hvis ikke, må saksbehandleren oppgi en begrunnelse og velge varighet (1–8 timer) før tilgang opprettes.
- **NAVident-videresending:** Saksbehandlerens NAVident legges til som HTTP-header (`x-forwarded-navident`) på alle forespørsler som sendes videre til backend.
- **Token-utveksling:** Brukerens token utveksles via NAIS sin token exchange-tjeneste for å få et OBO-token (on-behalf-of) mot JIT-APIet.

## Teknologier

- Kotlin / Spring Boot
- Spring Cloud Gateway (WebFlux)
- Spring Security (OAuth2 / OIDC)
- Thymeleaf (for begrunnelsesskjema)
- Deployes på NAIS (GCP)

