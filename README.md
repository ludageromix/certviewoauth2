# certviewoauth2

Serveur d'autorisation OAuth2 et serveur de ressources, développés en TDD strict.

L'authorization-server émet des jetons JWT signés en RS256 et publie ses clés publiques au
format JWKS. Le resource-server protège ses endpoints en vérifiant ces jetons, en récupérant
les clés par HTTP. Les deux applications sont indépendantes : elles ne partagent aucun code,
seulement le contrat JWKS.

> **Projet de démonstration.** Plusieurs mécanismes attendus d'un serveur OAuth2 de production
> sont absents — voir [Limites connues](#limites-connues). Ne pas déployer en l'état.

## Prérequis

Java 21. Maven n'a pas besoin d'être installé : chaque module embarque son wrapper (`mvnw`).

## Structure

Il n'y a pas de POM agrégateur à la racine. Les deux modules se construisent séparément.

| Module | Port | Rôle |
| --- | --- | --- |
| `authorization-server` | 8080 | Émission des jetons, publication du JWKS, rotation des clés |
| `resource-server` | 8081 | Endpoint protégé, vérification des jetons via le JWKS |

## Démarrage

Deux terminaux, l'authorization-server en premier :

```bash
cd authorization-server && ./mvnw spring-boot:run
```

```bash
cd resource-server && ./mvnw spring-boot:run
```

Deux situations à ne pas confondre :

- **L'authorization-server est éteint ou injoignable.** Le resource-server démarre quand même :
  le JWKS est récupéré paresseusement, à la première requête authentifiée. L'indisponibilité se
  manifeste alors par un 401 sur `/api/hello`, jamais par une erreur au démarrage.
- **La propriété `jwk-set-uri` est absente de la configuration.** Le démarrage échoue
  immédiatement — voir [Configuration](#configuration).

## Endpoints

### authorization-server (8080)

| Méthode | Chemin | Description |
| --- | --- | --- |
| `POST` | `/oauth/token` | Émet un jeton pour le `subject` fourni en formulaire |
| `GET` | `/.well-known/jwks.json` | Publie les clés publiques de vérification |
| `POST` | `/admin/rotate-keys` | Déclenche une rotation de la clé de signature |
| `GET` | `/ping` | Sonde de vie |

### resource-server (8081)

| Méthode | Chemin | Description |
| --- | --- | --- |
| `GET` | `/api/hello` | Protégé : exige un jeton vérifiable |

## Parcours complet

Obtenir un jeton :

```bash
curl -X POST http://localhost:8080/oauth/token -d "subject=certviewuser"
```

```json
{"access_token":"eyJraWQiOi...","token_type":"Bearer","expires_in":900}
```

L'appeler sur le resource-server :

```bash
curl http://localhost:8081/api/hello -H "Authorization: Bearer <access_token>"
```

```
Bonjour certviewuser
```

## Le jeton émis

En-tête RS256 portant le `kid` de la clé active ; corps limité à six claims — `iss`, `sub`,
`aud`, `iat`, `exp`, `jti`. Le `jti` est un UUID v4, unique par jeton.

`iat` et `exp` sont tronqués à la seconde, conformément au format NumericDate de la RFC 7519.
L'horloge est injectée (`java.time.Clock`), ce qui rend ces deux valeurs assertables exactement
en test.

Le `kid` n'est pas arbitraire : c'est le **JWK Thumbprint SHA-256** de la clé publique
(RFC 7638). Il est donc recalculable par quiconque possède la clé, et deux clés distinctes ne
peuvent pas produire le même identifiant.

## Validation côté resource-server

Un jeton est accepté seulement si les quatre conditions suivantes sont réunies :

| Contrôle | Rejet |
| --- | --- |
| Signature vérifiée par une clé du JWKS | 401 |
| `exp` non dépassé (tolérance d'horloge : 60 s) | 401 |
| `iss` égal à `certview.token.issuer` | 401 |
| `aud` contenant `certview.token.audience` | 401 |

Sans en-tête `Authorization`, la réponse est également 401.

Les deux dernières vérifications ne sont pas activées par défaut par Spring Security : un
resource-server configuré par le seul `jwk-set-uri` accepte tout jeton correctement signé, quels
que soient son émetteur et son destinataire déclarés. Elles sont ajoutées par
`JwtDecoderConfiguration`, qui combine `JwtValidators.createDefaultWithIssuer` — laquelle
conserve le contrôle d'expiration — et un `JwtAudienceValidator`.

Le resource-server **déclare ses propres attentes** sous `certview.token` plutôt que de lire la
configuration de l'émetteur. Les deux services évoluent ainsi séparément, et un désaccord se
manifeste par un rejet explicite plutôt que par une confiance implicite.

## Rotation des clés

```bash
curl -X POST http://localhost:8080/admin/rotate-keys
```

```json
{"active_kid":"V_XKgjoTCB51..."}
```

Une rotation **ajoute** une clé, elle n'en retire aucune. Les jetons émis avant la rotation
restent vérifiables jusqu'à leur expiration, puisque leur clé demeure publiée dans le JWKS. La
clé active apparaît en tête du tableau `keys`.

Côté resource-server, la prise en compte est automatique : un `kid` inconnu provoque un
rechargement du JWKS par Spring Security, sans redémarrage ni reconfiguration.

Le JWKS ne publie jamais que les membres publics d'une clé RSA — `kty`, `kid`, `use`, `alg`,
`n`, `e`. Les tests d'intégration appliquent une liste blanche fermée sur chaque clé publiée :
la présence de `d`, `p`, `q`, `dp`, `dq` ou `qi` fait échouer la suite.

## Configuration

`authorization-server/src/main/resources/application.yaml` — ce que le serveur inscrit dans les
jetons qu'il émet :

```yaml
certview:
  token:
    issuer: https://auth.certview.local
    audience: certview-api
    validity: 15m
```

`validity` accepte la syntaxe `Duration` de Spring (`15m`, `1h`, `PT30S`).

`resource-server/src/main/resources/application.yaml` — où trouver les clés, et ce que le
serveur exige des jetons qu'il reçoit :

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:8080/.well-known/jwks.json

certview:
  token:
    issuer: "https://auth.certview.local"
    audience: "certview-api"
```

Les valeurs des deux fichiers doivent concorder : `certview.token.issuer` et `.audience` du
resource-server sont comparés aux claims `iss` et `aud` produits par l'authorization-server. En
cas de divergence, tous les jetons sont rejetés en 401.

L'absence de `jwk-set-uri` fait échouer le démarrage du resource-server, plutôt que de le
laisser tomber silencieusement sur la sécurité par défaut de Spring Boot.

## Tests

```bash
cd authorization-server && ./mvnw test   # 38 tests
cd resource-server && ./mvnw test        # 8 tests
```

La suite couvre trois niveaux : composants isolés sans contexte Spring (`JwtTokenGenerator`,
`InMemoryRsaKeyProvider`), tranches web avec collaborateur mocké (`TokenControllerTest`), et
intégration en contexte complet — émission et vérification cryptographique réelles, rotation de
bout en bout, rejet des jetons expirés ou portant un `iss`/`aud` inattendu.

Le resource-server est testé contre un `MockWebServer` servant un JWKS de test, injecté par
`@DynamicPropertySource` : sa suite s'exécute sans que l'authorization-server tourne.

Les conventions de test et les invariants d'architecture sont documentés dans
[CLAUDE.md](CLAUDE.md). Le journal de développement figure dans
[docs/AI_WORKFLOW.md](docs/AI_WORKFLOW.md).

## Limites connues

**Aucune authentification client.** `POST /oauth/token` est ouvert : n'importe qui peut demander
un jeton pour n'importe quel sujet. Ni `client_id`/`client_secret`, ni `grant_type` de la
RFC 6749.

**`/admin/rotate-keys` n'est pas protégé.** N'importe quel appelant peut déclencher une rotation.

**Les clés ne survivent pas au redémarrage.** `InMemoryRsaKeyProvider` génère ses paires en
mémoire : après un redémarrage, les jetons émis auparavant deviennent invérifiables, et deux
instances de l'application signent avec des clés différentes. Un déploiement réel demande un
fournisseur adossé à un keystore ou à un coffre partagé — l'interface `RsaKeyProvider` est
prévue pour ça.

**Le registre de clés grossit sans limite.** Aucune politique de rétention : une clé compromise
resterait publiée indéfiniment.

**Aucune révocation.** Le `jti` est émis et unique par jeton, ce qui permet l'audit, mais rien ne
le consomme : aucun jeton ne peut être invalidé avant son expiration.

**Pas de document de découverte.** L'authorization-server ne publie pas
`/.well-known/openid-configuration` ; le resource-server doit être configuré avec l'URL du JWKS
en dur.
