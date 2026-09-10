package com.portagecybertech.certviewoauth2.authorizationserver;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
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
        // toPublicJWK() sur chacune : ce document est servi publiquement et ne doit jamais
        // contenir les membres prives d'une cle RSA (d, p, q, dp, dq, qi). La reduction est
        // appliquee ici a toutes les cles, y compris celles heritees des rotations passees.
        List<JWK> clesPubliques = rsaKeyProvider.getAllPublicKeys().stream()
                .map(JWK::toPublicJWK)
                .toList();

        return new JWKSet(clesPubliques).toJSONObject();
    }
}
