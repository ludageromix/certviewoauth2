package com.portagecybertech.certviewoauth2.authorizationserver;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test d'integration du endpoint d'emission, contexte Spring complet et sans mock.
 *
 * <p>Complementaire de {@code TokenControllerTest}, qui remplace le generateur par un mock et
 * ne verifie donc que le contrat HTTP. Ici le jeton est reellement signe par le bean
 * {@link RsaKeyProvider} de l'application : le test relie la reponse HTTP a la cle qui a servi
 * a la produire, ce qu'aucune tranche isolee ne peut faire.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Integration POST /oauth/token")
class TokenEndpointIntegrationTest {

    private static final String SUJET = "certviewtestuser";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RsaKeyProvider rsaKeyProvider;

    @Test
    @DisplayName("emet un jeton signe par la cle de l'application et portant le sujet demande")
    void emetUnJetonVerifiableAvecLaCleDeLApplication() throws Exception {
        String corps = mockMvc.perform(post("/oauth/token").param("subject", SUJET))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String accessToken = JsonPath.read(corps, "$.access_token");
        SignedJWT jwt = SignedJWT.parse(accessToken);

        assertThat(jwt.verify(new RSASSAVerifier(rsaKeyProvider.getAllPublicKeys().getFirst().toRSAPublicKey()))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo(SUJET);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(rsaKeyProvider.getSigningKey().kid());
    }
}
