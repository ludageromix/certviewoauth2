package com.portagecybertech.certviewoauth2.authorizationserver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

/**
 * Emet des jetons d'acces JWT signes en RS256.
 *
 * <p>Toutes les collaborations sont injectees par constructeur : la cle de signature via
 * {@link RsaKeyProvider}, le temps via {@link Clock}. Le composant ne connait ni la couche
 * HTTP ni le contexte Spring.</p>
 */
public class JwtTokenGenerator {

    private final RsaKeyProvider rsaKeyProvider;
    private final Clock clock;
    private final String issuer;
    private final String audience;
    private final Duration validity;

    public JwtTokenGenerator(RsaKeyProvider rsaKeyProvider,
                             Clock clock,
                             String issuer,
                             String audience,
                             Duration validity) {
        this.rsaKeyProvider = rsaKeyProvider;
        this.clock = clock;
        this.issuer = issuer;
        this.audience = audience;
        this.validity = validity;
    }

    /**
     * Emet un jeton signe pour le sujet donne.
     *
     * @param subject identifiant du sujet, obligatoire
     * @return le JWT en serialisation compacte et sa duree de validite
     * @throws IllegalArgumentException si le sujet est absent ou vide
     */
    public IssuedToken generateToken(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("Le sujet du jeton est obligatoire");
        }

        // NumericDate (RFC 7519) s'exprime en secondes : on tronque a la source plutot que
        // de laisser la serialisation arrondir, pour que iat et exp restent exacts.
        Instant issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(issuedAt.plus(validity)))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKeyProvider.getKeyId())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new RSASSASigner(rsaKeyProvider.getPrivateKey()));
        } catch (JOSEException e) {
            throw new IllegalStateException("Echec de la signature du jeton", e);
        }
        return new IssuedToken(jwt.serialize(), validity);
    }
}
