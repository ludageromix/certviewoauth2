package com.portagecybertech.certviewoauth2.authorizationserver;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests unitaires du composant {@code JwtTokenGenerator}.
 *
 * <p>Aucune dependance a la couche HTTP : ni {@code @SpringBootTest}, ni {@code MockMvc},
 * ni contexte Spring. Le composant est instancie a la main, ce qui impose que toutes ses
 * collaborations (cle RSA, horloge, parametres de jeton) soient injectees par constructeur.</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("JwtTokenGenerator")
class JwtTokenGeneratorTest {

    private static final String ISSUER = "https://auth.certview.local";
    private static final String AUDIENCE = "certview-resource-api";
    private static final Duration TOKEN_VALIDITY = Duration.ofMinutes(15);
    private static final String KEY_ID = "certview-signing-key-2026";
    private static final String SUBJECT = "utilisateur-certview";

    /**
     * Instant fixe volontairement porteur de millisecondes (.500) : il permet de verifier
     * que l'implementation tronque bien vers la seconde, comme l'exige le format NumericDate
     * de la RFC 7519, au lieu de laisser passer un arrondi silencieux.
     */
    private static final Instant NOW = Instant.parse("2026-09-07T10:15:30.500Z");

    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey;

    @Mock
    private RsaKeyProvider rsaKeyProvider;

    private JwtTokenGenerator generator;

    @BeforeAll
    static void genererLaPaireDeCles() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();
    }

    @BeforeEach
    void preparerLeGenerateur() {
        // lenient() : les cas d'erreur (sujet invalide) echouent avant d'atteindre le provider,
        // ce qui declencherait sinon une UnnecessaryStubbingException du runner strict.
        lenient().when(rsaKeyProvider.getPrivateKey()).thenReturn(privateKey);
        lenient().when(rsaKeyProvider.getKeyId()).thenReturn(KEY_ID);

        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        generator = new JwtTokenGenerator(rsaKeyProvider, clock, ISSUER, AUDIENCE, TOKEN_VALIDITY);
    }

    @Nested
    @DisplayName("En-tete JOSE")
    class EnTete {

        @Test
        @DisplayName("déclare être signé avec l'algorithme RS256")
        void utiliseLAlgorithmeRs256() throws Exception {
            SignedJWT jwt = SignedJWT.parse(generator.generateToken(SUBJECT));

            assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        }

        @Test
        @DisplayName("porte le kid fourni par le RsaKeyProvider")
        void exposeLeKidDuProvider() throws Exception {
            SignedJWT jwt = SignedJWT.parse(generator.generateToken(SUBJECT));

            assertThat(jwt.getHeader().getKeyID()).isEqualTo(KEY_ID);
        }

        @Test
        @DisplayName("place le kid dans l'en-tete et non dans le payload")
        void leKidResteDansLEnTete() throws Exception {
            SignedJWT jwt = SignedJWT.parse(generator.generateToken(SUBJECT));

            assertThat(jwt.getHeader().getKeyID()).isEqualTo(KEY_ID);
            assertThat(jwt.getJWTClaimsSet().getClaim("kid")).isNull();
        }

        @Test
        @DisplayName("est produit dans la serialisation compacte a trois segments")
        void produitUnJwtCompact() {
            String token = generator.generateToken(SUBJECT);

            assertThat(token).isNotBlank();
            assertThat(token.split("\\.")).hasSize(3);
        }
    }

    @Nested
    @DisplayName("Signature")
    class Signature {

        @Test
        @DisplayName("est verifiable avec la cle publique correspondante")
        void signatureVerifiableAvecLaClePublique() throws Exception {
            SignedJWT jwt = SignedJWT.parse(generator.generateToken(SUBJECT));

            assertThat(jwt.verify(new RSASSAVerifier(publicKey))).isTrue();
        }

        @Test
        @DisplayName("n'est pas verifiable avec une autre cle publique")
        void signatureRejeteeParUneAutreCle() throws Exception {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            RSAPublicKey autreClePublique = (RSAPublicKey) keyPairGenerator.generateKeyPair().getPublic();

            SignedJWT jwt = SignedJWT.parse(generator.generateToken(SUBJECT));

            assertThat(jwt.verify(new RSASSAVerifier(autreClePublique))).isFalse();
        }

        @Test
        @DisplayName("obtient cle privee et kid aupres du RsaKeyProvider")
        void delegueLObtentionDeLaCleAuProvider() {
            generator.generateToken(SUBJECT);

            verify(rsaKeyProvider, times(1)).getPrivateKey();
            verify(rsaKeyProvider, times(1)).getKeyId();
        }
    }

    @Nested
    @DisplayName("Claims")
    class Claims {

        @Test
        @DisplayName("contient iss, sub et aud")
        void contientLesClaimsDIdentite() throws Exception {
            JWTClaimsSet claims = claimsDe(generator.generateToken(SUBJECT));

            assertThat(claims.getIssuer()).isEqualTo(ISSUER);
            assertThat(claims.getSubject()).isEqualTo(SUBJECT);
            assertThat(claims.getAudience()).containsExactly(AUDIENCE);
        }

        @Test
        @DisplayName("declare iat a la seconde exacte de l'horloge injectee")
        void iatCorrespondALHorlogeFixe() throws Exception {
            JWTClaimsSet claims = claimsDe(generator.generateToken(SUBJECT));

            assertThat(claims.getIssueTime().toInstant())
                    .isEqualTo(NOW.truncatedTo(ChronoUnit.SECONDS));
        }

        @Test
        @DisplayName("declare exp a iat + duree de validite, sans approximation")
        void expCorrespondALaDureeDeValidite() throws Exception {
            JWTClaimsSet claims = claimsDe(generator.generateToken(SUBJECT));

            assertThat(claims.getExpirationTime().toInstant())
                    .isEqualTo(NOW.truncatedTo(ChronoUnit.SECONDS).plus(TOKEN_VALIDITY));
            assertThat(Duration.between(
                    claims.getIssueTime().toInstant(),
                    claims.getExpirationTime().toInstant()))
                    .isEqualTo(TOKEN_VALIDITY);
        }

        @Test
        @DisplayName("expose exactement les six claims attendus")
        void nExposeQueLesClaimsAttendus() throws Exception {
            JWTClaimsSet claims = claimsDe(generator.generateToken(SUBJECT));

            assertThat(claims.getClaims()).containsOnlyKeys("iss", "sub", "aud", "iat", "exp", "jti");
        }

        @Test
        @DisplayName("porte un jti non vide")
        void porteUnJtiNonVide() throws Exception {
            JWTClaimsSet claims = claimsDe(generator.generateToken(SUBJECT));

            assertThat(claims.getJWTID()).isNotBlank();
        }

        @Test
        @DisplayName("attribue un jti different a chaque jeton, a sujet et horloge identiques")
        void attribueUnJtiUniqueParJeton() throws Exception {
            String premierJti = claimsDe(generator.generateToken(SUBJECT)).getJWTID();
            String secondJti = claimsDe(generator.generateToken(SUBJECT)).getJWTID();

            assertThat(premierJti).isNotEqualTo(secondJti);
        }

        @Test
        @DisplayName("relit l'horloge a chaque appel plutot que de figer l'instant de construction")
        void relitLHorlogeAChaqueAppel() throws Exception {
            Instant plusTard = NOW.plusSeconds(60);
            JwtTokenGenerator generateurPlusTard = new JwtTokenGenerator(
                    rsaKeyProvider, Clock.fixed(plusTard, ZoneOffset.UTC), ISSUER, AUDIENCE, TOKEN_VALIDITY);

            JWTClaimsSet premier = claimsDe(generator.generateToken(SUBJECT));
            JWTClaimsSet second = claimsDe(generateurPlusTard.generateToken(SUBJECT));

            assertThat(Duration.between(
                    premier.getIssueTime().toInstant(),
                    second.getIssueTime().toInstant()))
                    .isEqualTo(Duration.ofSeconds(60));
        }
    }

    @Nested
    @DisplayName("Contrat d'entree")
    class ContratDEntree {

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   "})
        @DisplayName("refuse un sujet nul, vide ou blanc")
        void refuseUnSujetInvalide(String sujetInvalide) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> generator.generateToken(sujetInvalide));
        }

        /**
         * Remplace l'ancien test de distinction de jetons : depuis l'introduction du jti,
         * deux jetons different toujours, y compris si le sujet etait ignore. La propriete
         * reellement utile est le report du sujet fourni dans le claim sub, verifiee ici sur
         * plusieurs valeurs pour exclure une constante codee en dur et couvrir l'encodage
         * Base64URL du payload JSON.
         */
        @ParameterizedTest
        @ValueSource(strings = {"alice", "bob", "utilisateur-42", "prénom.accentué", "u"})
        @DisplayName("reporte le sujet fourni dans le claim sub")
        void reporteLeSujetFourniDansLeClaimSub(String sujet) throws Exception {
            JWTClaimsSet claims = claimsDe(generator.generateToken(sujet));

            assertThat(claims.getSubject()).isEqualTo(sujet);
        }
    }

    private static JWTClaimsSet claimsDe(String token) throws ParseException {
        return SignedJWT.parse(token).getJWTClaimsSet();
    }
}
