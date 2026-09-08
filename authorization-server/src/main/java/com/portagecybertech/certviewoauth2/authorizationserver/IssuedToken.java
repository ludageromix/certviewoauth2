package com.portagecybertech.certviewoauth2.authorizationserver;

import java.time.Duration;

/**
 * Jeton emis, accompagne de sa duree de validite.
 *
 * <p>Le couple est retourne d'un bloc pour que la duree annoncee a l'appelant et l'ecart
 * {@code iat}/{@code exp} inscrit dans le jeton proviennent d'une source unique : le endpoint
 * n'a pas a reconstituer {@code expires_in} depuis sa propre configuration, au risque de
 * diverger de ce que le jeton declare reellement.</p>
 *
 * @param token     la serialisation compacte du JWT signe
 * @param expiresIn la duree de validite, telle qu'inscrite dans le jeton
 */
public record IssuedToken(String token, Duration expiresIn) {
}
