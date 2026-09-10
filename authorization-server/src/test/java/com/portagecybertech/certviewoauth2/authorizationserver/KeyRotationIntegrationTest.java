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
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Scenario de rotation de cles de bout en bout, contexte Spring complet.
 *
 * <p>Les six etapes forment une sequence unique et ordonnee : la rotation modifie l'etat du
 * serveur, et les etapes suivantes n'ont de sens que sur cet etat. Les decouper en methodes
 * independantes les rendrait dependantes de l'ordre d'execution de JUnit, qui n'est pas
 * garanti — d'ou un test unique plutot que six.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@DisplayName("Integration rotation de cles")
class KeyRotationIntegrationTest {

    private static final String CHEMIN_JWKS = "/.well-known/jwks.json";
    private static final String CHEMIN_ROTATION = "/admin/rotate-keys";

    /**
     * Membres autorises dans un JWK publie. Liste fermee : la presence de {@code d}, {@code p},
     * {@code q}, {@code dp}, {@code dq} ou {@code qi} signifierait qu'une cle privee fuit dans
     * un document servi publiquement. La rotation multiplie les cles publiees, donc les
     * occasions de laisser passer l'une d'elles non reduite a sa partie publique.
     */
    private static final String[] MEMBRES_AUTORISES = {"kty", "kid", "use", "alg", "n", "e"};

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("publie la nouvelle cle, signe avec elle, et conserve la validite des anciens jetons")
    void rotationSansRuptureDeService() throws Exception {
        // --- Etape 1 : le JWKS initial ne publie qu'une cle ---
        List<Map<String, Object>> clesInitiales = clesDuJwks();
        assertThat(clesInitiales).hasSize(1);
        String kid1 = (String) clesInitiales.get(0).get("kid");
        assertThat(kid1).isNotBlank();

        // --- Etape 2 : un premier jeton est emis, signe par la cle courante ---
        SignedJWT jetonA = SignedJWT.parse(emettreJeton());
        assertThat(jetonA.getHeader().getKeyID()).isEqualTo(kid1);

        // --- Etape 3 : rotation declenchee par le endpoint d'administration ---
        mockMvc.perform(post(CHEMIN_ROTATION))
                .andExpect(status().isOk());

        // --- Etape 4 : les deux cles sont publiees, et rien d'autre que leurs membres publics ---
        List<Map<String, Object>> clesApresRotation = clesDuJwks();
        assertThat(clesApresRotation).hasSize(2);
        assertThat(clesApresRotation).allSatisfy(jwk -> assertThat(jwk).containsOnlyKeys(MEMBRES_AUTORISES));

        List<String> kids = clesApresRotation.stream().map(jwk -> (String) jwk.get("kid")).toList();
        assertThat(kids).contains(kid1).doesNotHaveDuplicates();
        String kid2 = kids.stream().filter(kid -> !kid.equals(kid1)).findFirst().orElseThrow();

        // --- Etape 5 : les jetons suivants sont signes par la nouvelle cle active ---
        SignedJWT jetonB = SignedJWT.parse(emettreJeton());
        assertThat(jetonB.getHeader().getKeyID()).isEqualTo(kid2);

        // --- Etape 6 : le jeton emis avant la rotation reste verifiable ---
        RSAKey ancienneCle = RSAKey.parse(jwkPortantLeKid(clesApresRotation, kid1));
        assertThat(jetonA.verify(new RSASSAVerifier(ancienneCle.toRSAPublicKey()))).isTrue();
    }

    private List<Map<String, Object>> clesDuJwks() throws Exception {
        String corps = mockMvc.perform(get(CHEMIN_JWKS))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(corps, "$.keys");
    }

    private String emettreJeton() throws Exception {
        String corps = mockMvc.perform(post("/oauth/token").param("subject", "certviewtestuser"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(corps, "$.access_token");
    }

    private static Map<String, Object> jwkPortantLeKid(List<Map<String, Object>> cles, String kid) {
        return cles.stream()
                .filter(jwk -> kid.equals(jwk.get("kid")))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Aucun JWK publie pour le kid " + kid));
    }
}
