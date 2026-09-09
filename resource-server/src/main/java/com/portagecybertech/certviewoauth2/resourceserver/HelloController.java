package com.portagecybertech.certviewoauth2.resourceserver;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint protege, accessible aux seuls porteurs d'un jeton verifiable.
 */
@RestController
public class HelloController {

    @GetMapping(path = "/api/hello")
    public String direBonjour(@AuthenticationPrincipal Jwt jwt) {
        // Le jeton est deja verifie par la chaine de filtres : si le handler est atteint, la
        // signature a ete validee contre le JWKS et le sujet provient d'un jeton authentique.
        return "Bonjour " + jwt.getSubject();
    }
}
