#Assistance apportée par Opus 5 de Claude Code dans la réalisation de ce projet

1. Prompt TDD : Spécification et TU pour Générateur de JWT OAuth2

Je développe un serveur OAuth2 sur le projet certviewoauth2 en TDD strict (Spring Boot 4.1.1, Java 21, module authorization-server, package com.portagecybertech.certviewoauth2.authorizationserver). Écris la classe de test complète (JUnit 5 / AssertJ / Mockito) pour valider le composant JwtTokenGenerator. Je souhaite tester sa méthode principale : String generateToken(String subject). Ne produis aucun code d'implémentation, uniquement la classe de test JwtTokenGeneratorTest. Voici les spécifications et contraintes à couvrir dans les cas de test : Payload & Header : Le token doit être un JWT signé en RS256. L'en-tête doit inclure le kid (Key ID), et le corps doit contenir les claims iss, sub, aud, iat, et exp. Gestion du temps déterministe : L'horloge java.time.Clock doit être injectée dans le composant. Dans ton test, utilise un Clock fixe (Clock.fixed(...)) pour valider les timestamps iat et exp de manière exacte, sans approximation. Abstraction des clés : Le composant doit dépendre d'une interface RsaKeyProvider pour obtenir la clé privée et le kid. Isolation : Zéro dépendance à la couche HTTP. En plus du code de test, ajoute une courte explication pour chaque décision non triviale (choix des assertions, stratégie d'inspection du header/payload JWT, gestion du Clock). 

    Résultat: une classe de test correcte, mais avec une nouvelle dépendance manquante (dans le pom.xml)

2. Prompt dépendance Nimbus manquante

J'ai une erreur avec Nimbus qui manque dans les dépendances. Tu peux ajouter le bon package dans le build Maven et vérifier que les imports passent bien ?Relance un build juste après pour être sûr que ça compile sans problème. 

    Résultat: Dépendance résolue, imports Nimbus OK. Le BOM Spring Boot 4.1.1 ne gère pas nimbus-jose-jwt. Je viens de perdre la garantie du BOM : c'est désormais à moi de suivre les mises à jour de sécurité de cette bibliothèque.

3. Prompt interface Key provider

Crée moi l'interface RsaKeyProvider dans le package com.portagecybertech.certviewoauth2.authorizationserver . Elle doit juste contenir deux méthodes : RSAPrivateKey getPrivateKey() et String getKeyId().

    Résultat: interface crée.

4. Prompt implémentation générateur de token

Maintenant, crée-moi la classe JwtTokenGenerator dans le même package. Elle doit générer et signer un JWT avec Nimbus (RS256) via une méthode generateToken(String subject). Injecte RsaKeyProvider, Clock, issuer, audience et validity dans le constructeur. N'oublie pas d'ajouter une vérification sur le subject (qu'il soit présent) et de gérer la date d'émission tronquée à la seconde via la Clock.

5. Prompt TDD Rouge pour l'unicité des jetons via le claim jti

On passe au cycle TDD pour ajouter un jti (JWT ID — l'identifiant unique du jeton utilisé pour éviter les attaques par rejeu, permettre la révocation et essentiel pour l'audit des jetons) dans JwtTokenGeneratorTest : Dans la classe Claims, ajoute deux tests : Le jeton contient un jti non vide (claims.getJWTID()). Deux appels successifs (même sujet, même horloge) produisent deux jti différents. Ajoute "jti" à la liste dans nExposeQueLesClaimsAttendus. propose moi plusieurs nouvelles approches pour le test produitDesJetonsDistinctsParSujet selon l'impact de ce nouvel identifiant unique avec pos/cons à l'appui pour que je décide de la décision à suivre. Lance .\mvnw test et montre-moi le rouge.

    Résultat: Les tests on bien été écris avec nExposeQueLesClaimsAttendus qui est repassé au rouge ce qui est normal, nous sommes au rouge pour les deux nouveaux. 4 proposition pour produitDesJetonsDistinctsParSujet: A — Asserter le claim sub, pas la chaîne du jeton B — Comparer les payloads en excluant jti C — Supprimer le test D — Paramétrer sur plusieurs sujets
    Je retiens D: Le point décisif est la constante codée en dur. Avec un seul sujet testé, une implémentation qui écrirait .subject("utilisateur-certview") en dur passerait tous les tests. C'est improbable dans du code écrit à la main, beaucoup moins improbable dans du code généré. Deux valeurs suffisent à fermer ce trou ; le paramétrage est simplement la façon propre de le faire.

6. Prompt de validation de l'option D du prompt(5)

Je valide l'option D.

    Résultat: il fait l'implémentation, et m'ajoute un helper "claimsDe" dans la classe globale de test, sauf qu'il ne généralise pas son utilisation pour les autres tests qui utilisent encore SignedJWT.parse(...).getJWTClaimsSet() en entier. Je vais lui demander de généraliser. 

7. Prompt pour uniformiser l'utilisation du helper claimsDe

Les autres tests continuent encore d'écrire SignedJWT.parse(...).getJWTClaimsSet() en entier. Je veux que tu généralise l'utilisation du helper que tu as créé. Fais moi savoir le nombre de modification effectuées et tous les endroits refactorisés.

    Résultat: il fait la réfactorisation, sauf pour des cas particulier et m'explique pourquoi.

8. Prompt TDD Vert pour l'implémentation du jti

Implémente la génération du jti dans JwtTokenGenerator (par exemple avec UUID.randomUUID().toString()) et ajoute-le aux claims du JWT. Relance .\mvnw test pour confirmer que tous les tests repassent au vert.

    Résultat: Implémentation effectué et tout est au vert.

9. Prompt TDD Rouge pour l'implémentation de InMemoryRsaKeyProvider

On passe au cycle TDD pour la classe InMemoryRsaKeyProvider (qui implémente RsaKeyProvider) dans le même package : Dans InMemoryRsaKeyProviderTest, écris deux tests : 1. Elle expose une clé privée RSA non nulle et un kid non nul/non vide. 2. Le kid correspond exactement au Thumbprint / à l'empreinte de la clé publique (calculé via SHA-256), et non à un UUID ou une valeur arbitraire. Exécute .\mvnw test et montre-moi le rouge.

    Résultat: deux nouveaux tests au rouge. Point d'ambiguité soulevé par l'assistant: Pour recalculer l'empreinte, le test a besoin de la clé publique. Or RsaKeyProvider ne déclare que getPrivateKey() et getKeyId(). J'ai donc écrit le test contre provider.getPublicKey(), ce qui ajoute une méthode à InMemoryRsaKeyProvider — sur la classe concrète, pas sur l'interface. Ma décision: Ajouter getPublicKey() à l'interface.

10. Prompt pour ajouter getPublicKey() à l'interface

Ajoute getPublickKey() à l'interface.

    Résultat: Contrat établi

11. Prompt d'amélioration des tests du prompt (9)

    Pour le test RSA : Au lieu de juste tester getAlgorithm() == "RSA", vérifie plutôt la taille de la clé, c'est plus solide. Remplace com.nimbusds.jose.util.Base64URL par le JDK standard : java.util.Base64.getUrlEncoder().withoutPadding().

12. Prompt d'ajout d'un test de stabilité sur getKeyId() (gage d'une non regression)

Ajoute un test de stabilité dans InMemoryRsaKeyProviderTest qui appelle getKeyId() deux fois et vérifie que c'est exactement la même valeur. Lance .\mvnw test et confirme-moi que le test échoue bien avant qu'on ne retouche à l'implémentation.

    Résultat: OK

13. Prompt d'implémentation de InMemoryRsaKeyProvider

Implémente la classe InMemoryRsaKeyProvider. Dans le constructeur : Génère une paire de clés RSA 2048 bits. Calcule le kid une seule fois via RSAKey.computeThumbprint() de Nimbus (ou votre calcul JWK) pour la stabilité. Stocke la clé privée, la clé publique et le kid dans des champs final. Relance .\mvnw test et vérifie que tous les tests repassent bien au vert.

    Résultat: Tout est correct, l'implémentation est réussie.

14. Prompt TDD du controler de génération de token

On continue le TDD de TokenControllerTest pour couvrir les 3 cas suivants: Cas nominal : POST /oauth/token avec subject=utilisateurcertview en formulaire (application/x-www-form-urlencoded). Attendu : HTTP 200, JSON avec access_token non vide, token_type = "Bearer", et expires_in. Sujet absent : POST sans paramètre. Attendu : HTTP 400. Sujet vide/blanc : POST avec subject= ou subject=   . Attendu : HTTP 400. Écris ces tests dans TokenControllerTest, lance .\mvnw test et montre-moi le rouge avant d'implémenter.

    Résultat: Il fait le taf, mais pose une ambiguïté sur l'origine expires_in. Il me propose deux solutions: Le contrôleur reçoit la durée en configuration ou generateToken renvoie un objet valeur (IssuedToken avec le jeton et sa durée) au lieu d'une String. La deuxième est meilleure, je la choisis.

15. Prompt validant l'option 2

Je valide la deuxième option

    Résultat: CATASTROPHE, l'agent vas au delà de ce que je lui ai demandé et passe à l'implémentation (au vert). Pour éviter qu'il ne s'emballe les pates si je lui demande de faire marche arrière, je décide de juste m'assurer qu'il a bien fait le travail que je ne lui ai pas demandé, et je m'assure de le scinder dans deux commits différents. J'ai aussi établi des règles claires à suivre durant tout le projet dans CLAUDE.md.

16. Prompt du test d'intégration (rattrapage)

écrit le test d'intégration TokenEndpointIntegrationTest: Utilise @SpringBootTest et @AutoConfigureMockMvc (contexte Spring complet, pas de mock) et injecte MockMvc ainsi que le bean RsaKeyProvider. Fais le test principal :
Fais un POST /oauth/token avec subject=certviewtestuser (formulaire). Récupère l'access_token du JSON de réponse. Parse-le avec SignedJWT.parse. Vérifie la signature avec RSASSAVerifier(provider.getPublicKey()). Vérifie que le sub est bien "certviewtestuser". Vérifie que le kid du header du JWT correspond exactement à provider.getKeyId(). Confirme-moi que tout passe au vert !

    Résultat: Vert!

17. Prompt TDD du endpoint des clés publiques

Crée JwksEndpointIntegrationTest avec @SpringBootTest et @AutoConfigureMockMvc (contexte Spring complet, vrai RsaKeyProvider injecté). Écris le test d'intégration pour GET /.well-known/jwks.json : Vérifie le statut 200 OK et la présence du tableau keys. Validation consommateur (Scénario réel) : Récupère la clé du JWKS publié, reconstruis la clé publique RSA (par exemple via Nimbus RSAKey.parse), et vérifie qu'elle valide la signature d'un jeton généré juste avant sur POST /oauth/token. Sécurité (liste blanche fermée) : Vérifie strictement que les seuls champs autorisés dans l'objet JWK sont kty, kid, use, alg, n et e. La présence de tout autre champ fait échouer le test. Lance les tests et arrête-toi strictement au rouge. N'écris pas encore l'implémentation.

    Résultat: test d'intégration correct et au rouge comme attendu!

18. Prompt d'implémentation de JwksController

Passes à l'implémentation je JwksController.
    Résultat: OK!

19. Prompt TDD — Test d'intégration HelloEndpointIntegrationTest (Resource Server)

crée HelloEndpointIntegrationTest dans le service resource-server (certviewoauth2\resource-server\src\test\java\com\portagecybertech\certviewoauth2\resourceserver). Exigences du test : Infrastructure propriétés dynamique : Utilise @SpringBootTest et @AutoConfigureMockMvc. Utilise un serveur de mock HTTP (MockWebServer ou WireMock) pour simuler le serveur d'autorisation. Injecte dynamiquement l'URL du JWKS avec @DynamicPropertySource sur la propriété spring.security.oauth2.resourceserver.jwt.jwk-set-uri en utilisant le port du serveur de mock. Contrainte dépendances : Si une dépendance de test manque dans le pom.xml (ex: mockwebserver ou wiremock), signale-le moi clairement sans modifier le pom.xml. Setup cryptographique du test : Génère une paire de clés RSA de test. Configure le serveur de mock pour servir la clé publique correspondante au format JWKS sur GET /.well-known/jwks.json. Les 3 cas de test pour GET /api/hello : Sans jeton : sans en-tête Authorization. Attendu : 401 Unauthorized. Jeton invalide : Authorization: Bearer ... . Attendu : 401 Unauthorized. Jeton valide : Signe un JWT valide avec la clé privée de test (avec sub="certviewuser"). Attendu : 200 OK et une réponse contenant le sujet "certviewuser". Lance les tests et arrête-toi strictement au rouge.

    Résultat: le test est fait et est au rouge, la dépendance mockwebserver est manquante, je l'ajoute dans le pom.xml.

20. Prompt implémentation du HelloController (Passage au Vert)

Écris le contrôleur HelloController : Déclare la classe sous @RestController. Crée le handler GET /api/hello. Récupère le jeton JWT via l'injection Spring Security @AuthenticationPrincipal Jwt. Renvoie une réponse contenant le sujet du jeton (jwt.getSubject()). Relance les tests et confirme-moi que toute la suite de tests passe désormais au vert !

    Résultat: Tout est OK. Il manque la config (port) du serveur de resource et la config de l'adresse du serveur d'autentication dans celui du serveur de resource.

21. Prompt de configuration du serveur de ressources sur le port 8081 et avec l'endpoint du serveur d'autorisation

 Configure le fichier application.yaml du serveur de ressources pour le faire tourner sur le port 8081 et pointer jwk-set-uri sur http://localhost:8080/.well-known/jwks.json (serveur d'autorisation)

    Résultat: Configuration en place.