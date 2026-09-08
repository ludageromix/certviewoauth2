package com.portagecybertech.certviewoauth2.authorizationserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests de la tranche web du endpoint d'emission de jetons.
 *
 * <p>{@code @WebMvcTest} ne charge que la couche MVC : le {@link JwtTokenGenerator} est
 * remplace par un mock, de sorte que ces tests portent sur le contrat HTTP (methode, encodage
 * du formulaire, codes de statut, forme du JSON) et non sur la cryptographie, deja couverte
 * par {@code JwtTokenGeneratorTest}.</p>
 */
@WebMvcTest(TokenController.class)
@DisplayName("POST /oauth/token")
class TokenControllerTest {

    private static final String JETON_EMIS = "jeton.factice.signe";
    private static final Duration VALIDITE = Duration.ofMinutes(15);

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtTokenGenerator jwtTokenGenerator;

    @BeforeEach
    void preparerLeGenerateur() {
        // lenient() : les cas d'erreur doivent etre rejetes avant tout appel au generateur.
        lenient().when(jwtTokenGenerator.generateToken(anyString())).thenReturn(new IssuedToken(JETON_EMIS, VALIDITE));
    }

    @Test
    @DisplayName("repond 200 et un corps OAuth2 pour un sujet valide")
    void emetUnJetonPourUnSujetValide() throws Exception {
        mockMvc.perform(post("/oauth/token").param("subject", "utilisateurcertview"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value(JETON_EMIS))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value((int) VALIDITE.toSeconds()));
    }

    @Test
    @DisplayName("transmet au generateur le sujet recu dans le formulaire")
    void transmetLeSujetAuGenerateur() throws Exception {
        mockMvc.perform(post("/oauth/token").param("subject", "utilisateurcertview"))
                .andExpect(status().isOk());

        verify(jwtTokenGenerator).generateToken("utilisateurcertview");
    }

    @Test
    @DisplayName("repond 400 quand le parametre subject est absent")
    void refuseUneRequeteSansSujet() throws Exception {
        mockMvc.perform(post("/oauth/token"))
                .andExpect(status().isBadRequest());

        verify(jwtTokenGenerator, never()).generateToken(anyString());
    }

    /**
     * Le rejet doit avoir lieu dans la couche web : le generateur est ici un mock qui ne leve
     * rien, donc un controleur qui se reposerait sur la validation de {@code JwtTokenGenerator}
     * renverrait 200 avec un jeton au sujet vide.
     */
    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    @DisplayName("repond 400 quand le sujet est vide ou blanc")
    void refuseUnSujetVideOuBlanc(String sujetInvalide) throws Exception {
        mockMvc.perform(post("/oauth/token").param("subject", sujetInvalide))
                .andExpect(status().isBadRequest());

        verify(jwtTokenGenerator, never()).generateToken(anyString());
    }
}
