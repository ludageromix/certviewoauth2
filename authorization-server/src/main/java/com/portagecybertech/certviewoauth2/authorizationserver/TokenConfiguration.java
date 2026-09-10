package com.portagecybertech.certviewoauth2.authorizationserver;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.Duration;

/**
 * Assemblage des composants d'emission de jetons.
 *
 * <p>Le cablage est explicite plutot qu'annote sur les classes : {@link JwtTokenGenerator} et
 * {@link InMemoryRsaKeyProvider} restent des objets ordinaires, instanciables et testables
 * sans contexte Spring.</p>
 */
@Configuration
public class TokenConfiguration {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Type de retour concret pour qu'une instance unique satisfasse les deux interfaces :
     * {@link RsaKeyProvider} pour le generateur et le JWKS, {@link RotatableKeyProvider} pour le
     * declencheur de rotation. Les consommateurs, eux, ne dependent que de l'interface qui les
     * concerne.
     */
    @Bean
    public InMemoryRsaKeyProvider rsaKeyProvider() {
        return new InMemoryRsaKeyProvider();
    }

    @Bean
    public JwtTokenGenerator jwtTokenGenerator(
            RsaKeyProvider rsaKeyProvider,
            Clock clock,
            @Value("${certview.token.issuer}") String issuer,
            @Value("${certview.token.audience}") String audience,
            @Value("${certview.token.validity}") Duration validity) {
        return new JwtTokenGenerator(rsaKeyProvider, clock, issuer, audience, validity);
    }
}
