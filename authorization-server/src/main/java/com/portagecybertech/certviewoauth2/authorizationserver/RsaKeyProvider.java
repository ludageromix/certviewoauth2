package com.portagecybertech.certviewoauth2.authorizationserver;

import com.nimbusds.jose.jwk.RSAKey;

import java.util.List;

/**
 * Abstraction fournissant la cle de signature courante et l'ensemble des cles publiques valides.
 *
 * <p>Elle isole le generateur de jetons de la provenance des cles : keystore, fichier PEM,
 * coffre externe ou paire generee en memoire pour les tests.</p>
 */
public interface RsaKeyProvider {

    /**
     * @return la cle active, celle dont doivent etre signes les jetons emis maintenant
     */
    SigningKey getSigningKey();

    /**
     * Toutes les cles publiques encore valides, cle active comprise. Apres une rotation, les
     * anciennes restent presentes : les jetons emis avant la rotation doivent demeurer
     * verifiables jusqu'a leur expiration.
     *
     * @return les cles publiques a publier dans le JWKS, la cle active en tete
     */
    List<RSAKey> getAllPublicKeys();
}
