# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commandes

Il n'y a pas de POM agrégateur à la racine : toutes les commandes Maven se lancent depuis `authorization-server/`.

```bash
cd authorization-server
./mvnw test                              # suite complète
./mvnw test -Dtest=JwtTokenGeneratorTest # une classe
./mvnw test -Dtest='JwtTokenGeneratorTest$Claims'          # une classe @Nested
./mvnw test -Dtest='JwtTokenGeneratorTest#porteUnJtiNonVide' # une méthode
./mvnw spring-boot:run                   # démarre le serveur
```

**Utiliser `./mvnw clean test` quand un test référence une classe de production qui n'existe pas encore** (phase rouge du TDD). Sans `clean`, javac peut laisser un `.class` de test issu d'un build échoué ; la compilation incrémentale le juge à jour, et surefire charge la classe périmée. L'erreur de compilation se transforme alors en `NoClassDefFoundError` à l'exécution — ou, pire, un test peut passer au vert à tort.

## Architecture

Le module `authorization-server` émet des jetons d'accès JWT signés en RS256. Tout tient dans un seul package, `com.portagecybertech.certviewoauth2.authorizationserver`.

**Les composants métier ne portent aucune annotation Spring.** `JwtTokenGenerator` et `InMemoryRsaKeyProvider` sont des objets ordinaires, assemblés explicitement par `TokenConfiguration` (`@Bean`). C'est délibéré et structurant : leurs tests s'instancient à la main, sans contexte Spring ni couche HTTP. Préserver cette propriété en ajoutant les nouveaux composants à `TokenConfiguration` plutôt qu'en les annotant `@Component`.

Chaîne de dépendances : `TokenController` → `JwtTokenGenerator` → `RsaKeyProvider` + `Clock`.

- **`Clock` est injecté**, jamais `Instant.now()`. Les tests utilisent `Clock.fixed(...)` pour asserter `iat` et `exp` à la valeur exacte. `TokenConfiguration` fournit `Clock.systemUTC()`.
- **`generateToken` renvoie `IssuedToken(String token, Duration expiresIn)`**, pas une `String`. Ce choix garantit que le `expires_in` de la réponse HTTP et l'écart `iat`/`exp` inscrit dans le jeton proviennent du même appel et ne peuvent pas diverger. Ne pas revenir à un retour `String` sans traiter cette divergence.
- **Les dates sont tronquées à la seconde** (`truncatedTo(ChronoUnit.SECONDS)`) à la source, une seule fois, avant de servir de base à `iat` et à `exp` — le format NumericDate de la RFC 7519 est en secondes.
- **Le `kid` est le JWK Thumbprint SHA-256 de la clé publique** (RFC 7638), pas un UUID. Calculé une fois dans le constructeur d'`InMemoryRsaKeyProvider` et stocké en `final` : il identifie la clé dans le futur JWKS et doit rester stable.
- **La validation du sujet est dupliquée volontairement** : `TokenController` rejette en 400 avant tout appel au générateur, et `JwtTokenGenerator` lève `IllegalArgumentException` pour son propre compte. Les tests du contrôleur mockent le générateur et vérifient `never()` — un rejet délégué au générateur produirait un 500, pas un 400.

`InMemoryRsaKeyProvider` régénère sa paire à chaque démarrage : les jetons émis avant un redémarrage deviennent invérifiables, et deux instances signent avec des clés différentes. Acceptable en développement seulement.

Configuration dans `application.yaml` sous `certview.token` : `issuer`, `audience`, `validity` (format `Duration` Spring, ex. `15m`).

Non implémenté à ce jour : endpoint JWKS, authentification du client (`client_id`/`client_secret`), `grant_type` de la RFC 6749. Le endpoint `/oauth/token` est ouvert.

## Dépendance Nimbus

`nimbus-jose-jwt` **n'est pas géré par le BOM Spring Boot 4.1.1** : sa version est épinglée à la main dans la propriété `nimbus-jose-jwt.version` du POM. Les mises à jour de sécurité de cette bibliothèque sont à suivre manuellement.

## Conventions de test

Le projet est développé en TDD strict : le test est écrit et exécuté au rouge avant toute implémentation. `docs/AI_WORKFLOW.md` journalise chaque prompt et son résultat — l'y ajouter fait partie du cycle.

- Noms de tests et `@DisplayName` en français, classes `@Nested` par thème (`EnTete`, `Signature`, `Claims`, `ContratDEntree`).
- **Les tests recalculent la spécification plutôt que d'appeler l'utilitaire de la librairie testée.** `InMemoryRsaKeyProviderTest` recompose le JWK canonique et le hache avec le `java.util.Base64` du JDK, là où l'implémentation utilise `RSAKey.computeThumbprint()` de Nimbus. Deux chemins indépendants, sinon le test ne vérifie que la cohérence de Nimbus avec lui-même.
- `nExposeQueLesClaimsAttendus` utilise `containsOnlyKeys` : tout claim ajouté doit d'abord être réclamé par un test.
- Helper `claimsDe(IssuedToken)` dans `JwtTokenGeneratorTest` pour parser le payload. Les tests qui inspectent l'en-tête JOSE ou vérifient la signature gardent `SignedJWT.parse(...)`, ayant besoin de l'objet complet.
- `lenient()` sur les stubs Mockito quand des cas d'erreur court-circuitent le collaborateur, pour éviter `UnnecessaryStubbingException`.
- Les tests de contrôleur sont des tranches `@WebMvcTest(TokenController.class)` avec `@MockitoBean JwtTokenGenerator`. Aucun test d'intégration ne couvre encore le trajet complet avec un vrai générateur.

## Rythme de travail

- Ne jamais enchaîner deux étapes sans validation explicite.
- Terminer ce qui est demandé, s'arrêter, attendre.
- Un refactoring et une nouvelle fonctionnalité ne se font jamais dans la même passe.
- Signaler toute décision non couverte par la demande au lieu de la prendre seul.

