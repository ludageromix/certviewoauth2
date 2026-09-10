package com.portagecybertech.certviewoauth2.authorizationserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests unitaires de {@code InMemoryRsaKeyProvider}, implementation de {@link RsaKeyProvider}
 * generant sa paire RSA en memoire au demarrage.
 */
@DisplayName("InMemoryRsaKeyProvider")
class InMemoryRsaKeyProviderTest {

    private static final Base64.Encoder ENCODEUR = Base64.getUrlEncoder().withoutPadding();

    private InMemoryRsaKeyProvider provider;

    @BeforeEach
    void creerLeProvider() {
        provider = new InMemoryRsaKeyProvider();
    }

    /**
     * La taille du modulus est verifiee plutot que le seul nom d'algorithme : "RSA" ne dit rien
     * de la robustesse, alors qu'une cle de 1024 bits — techniquement RSA — est aujourd'hui
     * hors d'usage pour signer des jetons. 2048 bits est le plancher exige par la RFC 7518
     * pour RS256. L'assertion est un minorant : elle laisse passer un futur passage a 4096.
     */
    @Test
    @DisplayName("expose une cle privee RSA d'au moins 2048 bits et un kid exploitable")
    void exposeUneClePriveeEtUnKid() {
        assertThat(provider.getSigningKey().privateKey()).isNotNull();
        assertThat(provider.getSigningKey().privateKey().getModulus().bitLength()).isGreaterThanOrEqualTo(2048);
        assertThat(provider.getSigningKey().kid()).isNotBlank();
    }

    /**
     * Le kid n'est pas une valeur arbitraire : c'est le JWK Thumbprint SHA-256 de la cle
     * publique, au sens de la RFC 7638. L'attendu est recalcule ici a la main, a partir des
     * membres requis d'une cle RSA ({@code e}, {@code kty}, {@code n}) serialises en JSON
     * canonique — cles triees par ordre lexicographique, sans espace — puis hache en SHA-256
     * et encode en Base64URL. Refaire le calcul plutot que d'appeler l'utilitaire de la
     * librairie garantit que le test verifie la specification et non le comportement de
     * l'implementation.
     */
    @Test
    @DisplayName("derive le kid du JWK Thumbprint SHA-256 de la cle publique")
    void leKidEstLEmpreinteDeLaClePublique() throws Exception {
        RSAPublicKey publicKey = provider.getAllPublicKeys().getFirst().toRSAPublicKey();

        String jwkCanonique = "{\"e\":\"" + base64Url(publicKey.getPublicExponent())
                + "\",\"kty\":\"RSA\",\"n\":\"" + base64Url(publicKey.getModulus()) + "\"}";
        byte[] empreinte = MessageDigest.getInstance("SHA-256")
                .digest(jwkCanonique.getBytes(StandardCharsets.UTF_8));
        String kidAttendu = ENCODEUR.encodeToString(empreinte);

        assertThat(provider.getSigningKey().kid()).isEqualTo(kidAttendu);
    }

    /**
     * Garde-fou de stabilite : le kid est publie dans l'en-tete de chaque jeton et sert au
     * consommateur a selectionner la cle dans le JWKS. S'il variait d'un appel a l'autre, les
     * jetons deja emis deviendraient invalidables. Le test protege contre une implementation
     * qui regenererait la paire de cles ou recalculerait une valeur aleatoire a chaque appel.
     */
    @Test
    @DisplayName("retourne le meme kid a chaque appel")
    void leKidEstStableEntreDeuxAppels() {
        assertThat(provider.getSigningKey().kid()).isEqualTo(provider.getSigningKey().kid());
    }

    /**
     * Encode un entier en Base64URL selon la convention JWK (RFC 7518, section 6.3.1) :
     * representation big-endian non signee, longueur minimale. {@link BigInteger#toByteArray()}
     * prefixe un octet nul quand le bit de poids fort est a 1, pour porter le signe — il faut
     * le retirer, sinon l'empreinte calculee differe de celle de la specification.
     */
    private static String base64Url(BigInteger valeur) {
        byte[] octets = valeur.toByteArray();
        if (octets.length > 1 && octets[0] == 0) {
            octets = Arrays.copyOfRange(octets, 1, octets.length);
        }
        return ENCODEUR.encodeToString(octets);
    }
}
