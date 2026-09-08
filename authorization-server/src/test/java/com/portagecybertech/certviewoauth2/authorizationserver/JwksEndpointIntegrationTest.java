package com.portagecybertech.certviewoauth2.authorizationserver;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test d'integration du JWKS publie, contexte Spring complet et sans mock.
 *
 * <p>Le JWKS est le point de contact avec les consommateurs de jetons : il doit exposer de quoi
 * verifier une signature, et rien de plus. Ces tests se placent du cote du consommateur, en
 * reconstruisant la cle publique depuis le document publie plutot qu'en interrogeant le bean.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Integration GET /.well-known/jwks.json")
class JwksEndpointIntegrationTest {

    private static final String CHEMIN_JWKS = "/.well-known/jwks.json";

    /**
     * Membres autorises dans le JWK publie. La liste est fermee : tout champ supplementaire fait
     * echouer le test. L'enjeu est la fuite de la cle privee — un JWK RSA complet contient
     * {@code d}, {@code p}, {@code q}, {@code dp}, {@code dq} et {@code qi}, et publier l'objet
     * issu de la paire sans le reduire a sa partie publique compromettrait la signature.
     */
    private static final List<String> MEMBRES_AUTORISES = List.of("kty", "kid", "use", "alg", "n", "e");

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("repond 200 avec un tableau keys non vide")
    void publieUnTableauDeCles() throws Exception {
        mockMvc.perform(get(CHEMIN_JWKS))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isNotEmpty());
    }

    @Test
    @DisplayName("n'expose que les membres publics du JWK")
    void nExposeQueLesMembresPublics() throws Exception {
        Map<String, Object> jwk = premiereCleDuJwks();

        assertThat(jwk).containsOnlyKeys(MEMBRES_AUTORISES.toArray(String[]::new));
    }

    /**
     * Scenario consommateur de bout en bout : un client qui ne connait que l'URL du serveur
     * recupere le JWKS, reconstruit la cle publique et verifie un jeton. C'est le seul test qui
     * relie le document publie au jeton reellement emis — si le JWKS exposait une autre cle que
     * celle de signature, tous les autres tests resteraient verts.
     */
    @Test
    @DisplayName("publie la cle qui valide la signature d'un jeton fraichement emis")
    void laClePublieeValideUnJetonEmis() throws Exception {
        String corpsJeton = mockMvc.perform(post("/oauth/token").param("subject", "certviewtestuser"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        SignedJWT jwt = SignedJWT.parse(JsonPath.read(corpsJeton, "$.access_token"));

        RSAKey clePubliee = RSAKey.parse(premiereCleDuJwks());
        RSAPublicKey clePublique = clePubliee.toRSAPublicKey();

        assertThat(jwt.verify(new RSASSAVerifier(clePublique))).isTrue();
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(clePubliee.getKeyID());
    }

    private Map<String, Object> premiereCleDuJwks() throws Exception {
        String corps = mockMvc.perform(get(CHEMIN_JWKS))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(corps, "$.keys[0]");
    }
}
