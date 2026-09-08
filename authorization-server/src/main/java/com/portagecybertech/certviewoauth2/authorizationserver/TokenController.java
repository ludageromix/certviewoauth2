package com.portagecybertech.certviewoauth2.authorizationserver;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * Endpoint d'emission de jetons d'acces.
 */
@RestController
public class TokenController {

    private final JwtTokenGenerator jwtTokenGenerator;

    public TokenController(JwtTokenGenerator jwtTokenGenerator) {
        this.jwtTokenGenerator = jwtTokenGenerator;
    }

    @PostMapping(path = "/oauth/token")
    public ResponseEntity<TokenResponse> emettreJeton(@RequestParam("subject") String subject) {
        // Le sujet est valide ici plutot que de laisser remonter l'IllegalArgumentException du
        // generateur : la couche web doit repondre 400, pas 500, et le rejet doit intervenir
        // avant toute sollicitation de la cle de signature.
        if (subject.isBlank()) {
            throw new ResponseStatusException(BAD_REQUEST, "Le parametre subject est obligatoire");
        }

        IssuedToken jeton = jwtTokenGenerator.generateToken(subject);
        return ResponseEntity.ok(new TokenResponse(jeton.token(), "Bearer", jeton.expiresIn().toSeconds()));
    }

    /**
     * Corps de reponse au format attendu par la RFC 6749, section 5.1.
     */
    record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn) {
    }
}
