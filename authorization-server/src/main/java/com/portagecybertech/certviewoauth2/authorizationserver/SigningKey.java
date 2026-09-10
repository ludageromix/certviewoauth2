package com.portagecybertech.certviewoauth2.authorizationserver;

import java.security.interfaces.RSAPrivateKey;

/**
 * Cle de signature active, indissociable de son identifiant.
 *
 * <p>Le couple est retourne d'un bloc pour qu'une rotation concurrente ne puisse pas glisser
 * entre la lecture du {@code kid} et celle de la cle privee : un jeton signe par la nouvelle
 * cle mais annonçant l'ancien {@code kid} dans son en-tete serait rejete par tout consommateur.</p>
 *
 * @param kid        identifiant publie dans l'en-tete JOSE et dans le JWKS
 * @param privateKey cle privee correspondante
 */
public record SigningKey(String kid, RSAPrivateKey privateKey) {
}
