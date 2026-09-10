package com.portagecybertech.certviewoauth2.authorizationserver;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Declenche la rotation de la cle de signature.
 *
 * <p><strong>Endpoint de demonstration, non securise.</strong> Il n'exige aujourd'hui aucune
 * authentification : n'importe quel appelant peut provoquer une rotation. Avant tout
 * deploiement, il doit etre restreint a un appelant administrateur — ou retire au profit d'une
 * rotation programmee, hors surface HTTP.</p>
 */
@RestController
public class KeyRotationController {

    private final InMemoryRsaKeyProvider rsaKeyProvider;

    public KeyRotationController(InMemoryRsaKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    @PostMapping(path = "/admin/rotate-keys")
    public RotationResponse rotationnerLesCles() {
        return new RotationResponse(rsaKeyProvider.rotateKeys());
    }

    /**
     * @param activeKid identifiant de la cle desormais utilisee pour signer
     */
    record RotationResponse(@JsonProperty("active_kid") String activeKid) {
    }
}
