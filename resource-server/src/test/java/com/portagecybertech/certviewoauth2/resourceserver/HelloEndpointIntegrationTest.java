package com.portagecybertech.certviewoauth2.resourceserver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test d'integration de l'endpoint protege, contexte Spring complet.
 *
 * <p>Le serveur d'autorisation est simule par un {@link MockWebServer} qui sert un JWKS de test.
 * Le resource server est ainsi valide dans son mode de fonctionnement reel — recuperation des
 * cles par HTTP, verification de signature — sans dependre du module authorization-server.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Integration GET /api/hello")
class HelloEndpointIntegrationTest {

    private static final String CHEMIN_JWKS = "/.well-known/jwks.json";
    private static final String SUJET = "certviewuser";

    /**
     * Paire de test, initialisee au chargement de la classe : {@link DynamicPropertySource} et
     * le demarrage du contexte interviennent apres, et ont besoin du serveur deja demarre.
     */
    private static final RSAKey CLE_DE_TEST = genererCleDeTest();

    /** Seconde paire, absente du JWKS au demarrage : elle n'y est ajoutee que par la rotation. */
    private static final RSAKey CLE_DE_ROTATION = genererCleDeTest();

    /**
     * Contenu courant du JWKS servi par le mock. Mutable et {@code volatile} : la rotation le
     * remplace depuis le thread de test, le dispatcher le lit depuis un thread du serveur.
     */
    private static volatile JWKSet jwksPublie = new JWKSet(CLE_DE_TEST.toPublicJWK());

    private static MockWebServer serveurAutorisation;

    @Autowired
    private MockMvc mockMvc;

    @BeforeAll
    static void demarrerLeServeurAutorisation() throws Exception {
        serveurAutorisation = new MockWebServer();
        serveurAutorisation.setDispatcher(new Dispatcher() {
            @NotNull
            @Override
            public MockResponse dispatch(@NotNull RecordedRequest requete) {
                // Un dispatcher plutot qu'une file de reponses : Spring Security peut recharger
                // le JWKS a tout moment, et une file epuisee ferait echouer un test au hasard.
                if (CHEMIN_JWKS.equals(requete.getPath())) {
                    return new MockResponse()
                            .setResponseCode(200)
                            .setHeader("Content-Type", "application/json")
                            .setBody(jwksPublie.toString());
                }
                return new MockResponse().setResponseCode(404);
            }
        });
        serveurAutorisation.start();
    }

    @AfterAll
    static void arreterLeServeurAutorisation() throws Exception {
        serveurAutorisation.shutdown();
    }

    @DynamicPropertySource
    static void pointerVersLeJwksDeTest(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> serveurAutorisation.url(CHEMIN_JWKS).toString());
    }

    @Test
    @DisplayName("repond 401 sans en-tete Authorization")
    void refuseUneRequeteSansJeton() throws Exception {
        mockMvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("repond 401 pour un jeton non verifiable")
    void refuseUnJetonInvalide() throws Exception {
        mockMvc.perform(get("/api/hello").header(AUTHORIZATION, "Bearer jeton.non.valide"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("repond 200 et nomme le sujet pour un jeton signe par la cle publiee")
    void accepteUnJetonSigneParLaCleDuJwks() throws Exception {
        mockMvc.perform(get("/api/hello").header(AUTHORIZATION, "Bearer " + jetonSignePar(CLE_DE_TEST)))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(SUJET)));
    }

    /**
     * Rotation a chaud, du point de vue du resource server : une cle apparait dans le JWKS
     * pendant que l'application tourne, sans redemarrage ni reconfiguration. Le code de
     * production n'est pas sollicite differemment — seul le document distant change.
     */
    @Test
    @DisplayName("accepte un jeton signe par une cle ajoutee au JWKS apres le premier appel")
    void accepteUneCleAjouteeParRotation() throws Exception {
        // 1. La premiere cle est la seule publiee : le resource server charge le JWKS ici.
        mockMvc.perform(get("/api/hello").header(AUTHORIZATION, "Bearer " + jetonSignePar(CLE_DE_TEST)))
                .andExpect(status().isOk());

        // 2. Le serveur d'autorisation publie desormais les deux cles.
        jwksPublie = new JWKSet(List.of(CLE_DE_TEST.toPublicJWK(), CLE_DE_ROTATION.toPublicJWK()));

        // 3. Un kid inconnu du cache doit provoquer un rechargement du JWKS.
        mockMvc.perform(get("/api/hello").header(AUTHORIZATION, "Bearer " + jetonSignePar(CLE_DE_ROTATION)))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(SUJET)));

        // 4. L'ancienne cle reste valide : une rotation ajoute, elle ne remplace pas.
        mockMvc.perform(get("/api/hello").header(AUTHORIZATION, "Bearer " + jetonSignePar(CLE_DE_TEST)))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(SUJET)));
    }

    private static String jetonSignePar(RSAKey cle) throws JOSEException {
        Instant maintenant = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(SUJET)
                .issueTime(Date.from(maintenant))
                .expirationTime(Date.from(maintenant.plus(Duration.ofMinutes(15))))
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(cle.getKeyID())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(cle.toRSAPrivateKey()));
        return jwt.serialize();
    }

    private static RSAKey genererCleDeTest() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyIDFromThumbprint(true)
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Echec de generation de la cle de test", e);
        }
    }
}
