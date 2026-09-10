package com.portagecybertech.certviewoauth2.authorizationserver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Implementation de {@link RsaKeyProvider} generant ses paires RSA en memoire.
 *
 * <p>Les cles ne survivent pas au redemarrage : les jetons emis auparavant deviennent
 * inverifiables. Convient au developpement et aux tests ; un deploiement multi-instance ou
 * durable demande un fournisseur adosse a un keystore ou a un coffre partage.</p>
 */
public class InMemoryRsaKeyProvider implements RsaKeyProvider, RotatableKeyProvider {

    private static final int TAILLE_CLE_BITS = 2048;

    /** Cle active en tete, anciennes cles ensuite. Ecrit par les rotations, lu par le JWKS. */
    private final List<RSAKey> clesPubliques = new CopyOnWriteArrayList<>();

    private volatile SigningKey cleActive;

    public InMemoryRsaKeyProvider() {
        installerNouvelleCle();
    }

    @Override
    public SigningKey getSigningKey() {
        return cleActive;
    }

    @Override
    public List<RSAKey> getAllPublicKeys() {
        return List.copyOf(clesPubliques);
    }

    @Override
    public String rotateKeys() {
        return installerNouvelleCle();
    }

    /**
     * La cle publique est publiee avant que la cle active ne change : dans l'intervalle, un
     * jeton reste signe par l'ancienne cle, elle-meme toujours dans le registre. L'ordre inverse
     * ouvrirait une fenetre ou des jetons seraient signes par une cle absente du JWKS.
     */
    private String installerNouvelleCle() {
        RSAKey jwk = genererPaireRsa();
        clesPubliques.add(0, jwk.toPublicJWK());
        try {
            cleActive = new SigningKey(jwk.getKeyID(), jwk.toRSAPrivateKey());
        } catch (JOSEException e) {
            throw new IllegalStateException("Cle privee RSA inexploitable", e);
        }
        return jwk.getKeyID();
    }

    /**
     * Le {@code kid} est derive du JWK Thumbprint SHA-256 (RFC 7638) plutot que tire au hasard :
     * il est ainsi reproductible a partir de la cle elle-meme, et deux rotations ne peuvent pas
     * produire le meme identifiant pour des cles differentes.
     */
    private static RSAKey genererPaireRsa() {
        try {
            return new RSAKeyGenerator(TAILLE_CLE_BITS)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyIDFromThumbprint(true)
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Echec de generation de la paire RSA", e);
        }
    }
}
