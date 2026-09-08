package com.portagecybertech.certviewoauth2.authorizationserver;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Publie le jeu de cles publiques permettant de verifier les jetons emis (RFC 7517).
 */
@RestController
public class JwksController {

    private final RsaKeyProvider rsaKeyProvider;

    public JwksController(RsaKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    @GetMapping(path = "/.well-known/jwks.json")
    public Map<String, Object> publierJwks() {
        RSAKey jwk = new RSAKey.Builder(rsaKeyProvider.getPublicKey())
                .keyID(rsaKeyProvider.getKeyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();

        // toPublicJWK() est redondant avec un builder alimente par la seule cle publique, mais
        // il rend la reduction explicite : ce document est servi publiquement et ne doit jamais
        // contenir les membres prives d'une cle RSA (d, p, q, dp, dq, qi).
        return new JWKSet(jwk.toPublicJWK()).toJSONObject();
    }
}
