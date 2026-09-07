package com.portagecybertech.certviewoauth2.authorizationserver;

import java.security.interfaces.RSAPrivateKey;

/**
 * Abstraction fournissant la cle privee RSA de signature et son identifiant.
 *
 * <p>Elle isole le generateur de jetons de la provenance de la cle : keystore, fichier PEM,
 * coffre externe ou paire generee en memoire pour les tests.</p>
 */
public interface RsaKeyProvider {

    /**
     * @return la cle privee RSA utilisee pour signer les jetons
     */
    RSAPrivateKey getPrivateKey();

    /**
     * @return le {@code kid} publie dans l'en-tete JOSE, permettant au consommateur
     *         de selectionner la cle publique correspondante dans le JWKS
     */
    String getKeyId();
}
