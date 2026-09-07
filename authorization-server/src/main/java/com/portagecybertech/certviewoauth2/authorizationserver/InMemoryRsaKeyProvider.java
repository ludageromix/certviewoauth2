package com.portagecybertech.certviewoauth2.authorizationserver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Implementation de {@link RsaKeyProvider} generant sa paire RSA en memoire a la construction.
 *
 * <p>La paire ne survit pas au redemarrage : les jetons emis avant un redemarrage deviennent
 * invérifiables. Convient au developpement et aux tests ; un deploiement multi-instance ou
 * durable demande un fournisseur adosse a un keystore ou a un coffre partage.</p>
 */
public class InMemoryRsaKeyProvider implements RsaKeyProvider {

    private static final int TAILLE_CLE_BITS = 2048;

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final String keyId;

    public InMemoryRsaKeyProvider() {
        KeyPair keyPair = genererPaireRsa();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
        // Le kid est calcule une fois pour toutes : il identifie la cle dans le JWKS et doit
        // rester identique pendant toute la duree de vie du fournisseur.
        this.keyId = calculerThumbprint(this.publicKey);
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public String getKeyId() {
        return keyId;
    }

    private static KeyPair genererPaireRsa() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(TAILLE_CLE_BITS);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithme RSA indisponible sur cette JVM", e);
        }
    }

    /**
     * Derive le {@code kid} du JWK Thumbprint SHA-256 de la cle publique (RFC 7638), de sorte
     * que l'identifiant soit reproductible a partir de la cle elle-meme plutot qu'arbitraire.
     */
    private static String calculerThumbprint(RSAPublicKey publicKey) {
        try {
            return new RSAKey.Builder(publicKey).build().computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new IllegalStateException("Echec du calcul de l'empreinte de la cle publique", e);
        }
    }
}
