package com.portagecybertech.certviewoauth2.authorizationserver;

/**
 * Capacite de rotation, separee de {@link RsaKeyProvider}.
 *
 * <p>Tous les fournisseurs ne savent pas tourner leurs cles : un fournisseur adosse a un
 * keystore externe peut n'exposer que des cles gerees ailleurs. Isoler cette operation evite
 * d'imposer une methode non implementable aux fournisseurs en lecture seule, et permet au
 * declencheur de rotation de ne dependre que de ce dont il a besoin.</p>
 */
public interface RotatableKeyProvider {

    /**
     * Genere une nouvelle cle, la promeut en cle active et conserve les precedentes.
     *
     * @return le {@code kid} de la nouvelle cle active
     */
    String rotateKeys();
}
