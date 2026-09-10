package com.portagecybertech.certviewoauth2.resourceserver;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Durcit la validation des jetons au-dela de la seule signature.
 *
 * <p>Par defaut, un resource server configure par {@code jwk-set-uri} ne verifie que la
 * signature et les bornes temporelles : tout jeton signe par une cle du JWKS est accepte, quels
 * que soient son emetteur et son destinataire declares. Cette configuration ajoute les deux
 * verifications manquantes.</p>
 *
 * <p>Les attentes sont declarees ici, sous {@code certview.token} : le resource server dit ce
 * qu'il accepte plutot que de lire la configuration de l'emetteur. Les deux services peuvent
 * ainsi evoluer separement, et un desaccord se manifeste par un rejet explicite.</p>
 */
@Configuration
public class JwtDecoderConfiguration {

    @Bean
    public JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri,
            @Value("${certview.token.issuer}") String issuer,
            @Value("${certview.token.audience}") String audience) {

        // Construit sur le meme jwk-set-uri : la recuperation des cles, son cache et son
        // rechargement sur kid inconnu restent ceux de Spring Security. Seule la validation
        // des claims est remplacee.
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

        // createDefaultWithIssuer conserve les validateurs par defaut — dont exp et nbf — et
        // leur ajoute iss. Un simple JwtIssuerValidator aurait desactive la verification
        // d'expiration en remplacant la chaine par defaut.
        OAuth2TokenValidator<Jwt> validateurs = new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer),
                new JwtAudienceValidator(audience));
        decoder.setJwtValidator(validateurs);

        return decoder;
    }
}
