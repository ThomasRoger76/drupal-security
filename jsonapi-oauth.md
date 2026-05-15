# JSON:API & OAuth2 — Sécurité Drupal 11

## Vue d'ensemble

JSON:API est intégré dans Drupal core depuis D8.7. Simple OAuth (contrib) fournit OAuth2. Ces deux modules ensemble forment la base des API découplées (headless/decoupled Drupal).

---

## 1. Contrôle d'accès JSON:API

### hook_jsonapi_ENTITY_TYPE_filter_access

Contrôle qui peut filtrer les entités via les paramètres `filter[]` de l'API.

```php
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\jsonapi\Access\JsonApiAccessInterface;

/**
 * Implements hook_jsonapi_node_filter_access().
 *
 * Contrôle l'accès aux filtres JSON:API sur les nœuds.
 */
function mon_module_jsonapi_node_filter_access(
  EntityTypeInterface $entity_type,
  AccountInterface $account
): array {
  return [
    // Accès à TOUS les nœuds (publiés ou non)
    JSONAPI_FILTER_AMONG_ALL => AccessResult::allowedIfHasPermission(
      $account,
      'bypass node access'
    )->cachePerUser()->addCacheTags(['node_list']),

    // Accès uniquement aux nœuds publiés
    JSONAPI_FILTER_AMONG_PUBLISHED => AccessResult::allowedIfHasPermission(
      $account,
      'access content'
    )->cachePerUser(),

    // Accès aux nœuds propres à l'utilisateur (publiés ou non)
    JSONAPI_FILTER_AMONG_OWN => AccessResult::allowedIfHasPermission(
      $account,
      'view own unpublished content'
    )->cachePerUser(),
  ];
}
```

### Restreindre les bundles exposés

```php
// Via jsonapi_extras (module contrib recommandé) :
// Admin > Configuration > Web services > JSON:API > Resource overrides

// Via hook pour désactiver programmatiquement un bundle :
function mon_module_jsonapi_resource_type_build_alter(array &$resource_types): void {
  // Désactiver l'exposition du type 'internal_page'
  if (isset($resource_types['node--internal_page'])) {
    $disabled = $resource_types['node--internal_page']->getDeserializationTargetClass();
    // Supprimer complètement le type de l'API
    unset($resource_types['node--internal_page']);
  }
}
```

### Exclure des champs sensibles

```php
// Avec jsonapi_extras : désactiver les champs via l'interface admin
// Ou via hook (natif D11+) :
function mon_module_jsonapi_resource_type_build_alter(array &$resource_types): void {
  if (isset($resource_types['user--user'])) {
    // Récupérer le type et retirer les champs sensibles
    // Note : utiliser jsonapi_extras pour une gestion fine des champs
  }
}
```

> **Règle de sécurité :** Ne jamais exposer `mail`, `pass`, `field_api_key`, `field_stripe_customer_id` ou tout champ contenant des données personnelles sensibles via JSON:API sans contrôle d'accès explicite.

---

## 2. Configuration CORS — Frontend découplé

```yaml
# web/sites/default/services.yml
parameters:
  cors.config:
    enabled: true
    allowedHeaders:
      - 'Content-Type'
      - 'Authorization'
      - 'X-CSRF-Token'
      - 'Accept'
      - 'X-Requested-With'
    allowedOrigins:
      - 'https://monapp.com'
      - 'https://staging.monapp.com'
      - 'http://localhost:3000'    # Dev frontend Next.js
      - 'http://localhost:5173'    # Dev frontend Vite
    allowedMethods:
      - 'GET'
      - 'POST'
      - 'PATCH'
      - 'DELETE'
      - 'OPTIONS'
    exposedHeaders:
      - 'Link'
      - 'X-CSRF-Token'
    maxAge: 1000
    supportsCredentials: true
```

> `allowedOrigins: ['*']` est INTERDIT en production — cela ouvre l'API à n'importe quel domaine.
> Après modification de `services.yml`, vider le cache : `docker compose exec php drush cr`

---

## 3. Simple OAuth — Installation et configuration

```bash
composer require drupal/simple_oauth
docker compose exec php drush en simple_oauth -y

# Générer les clés RSA (stocker HORS du webroot)
docker compose exec php drush simple-oauth:create-keys /var/www/private/oauth_keys

# Structure générée :
# /var/www/private/oauth_keys/private.key
# /var/www/private/oauth_keys/public.key
```

```php
// settings.php — pointer vers les clés
$config['simple_oauth.settings']['public_key']  = '/var/www/private/oauth_keys/public.key';
$config['simple_oauth.settings']['private_key'] = '/var/www/private/oauth_keys/private.key';
```

### Flows OAuth2 disponibles

| Flow | Usage | Sécurité |
|------|-------|----------|
| **Client Credentials** | Machine-to-machine, microservices | ✅ Recommandé pour les API serveur |
| **Authorization Code** | SPA, applications mobiles (avec PKCE) | ✅ Recommandé pour les apps utilisateur |
| **Refresh Token** | Renouveler les tokens sans re-login | ✅ Utiliser avec expiration courte |
| **Password** (Resource Owner) | Déprécié OAuth2.1 | ❌ Ne pas utiliser |

### Exemple : Client Credentials flow

```bash
# 1. Créer un Client OAuth2 dans Drupal admin
# Admin > Configuration > People > Simple OAuth > Clients > Add

# 2. Obtenir un token (machine-to-machine)
curl -X POST https://monsite.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=MON_CLIENT_ID&client_secret=MON_SECRET&scope=mon_scope"

# Réponse :
# {"access_token":"eyJ...", "token_type":"Bearer", "expires_in":300}

# 3. Appeler JSON:API avec le token
curl -X GET https://monsite.com/jsonapi/node/article \
  -H "Authorization: Bearer eyJ..."
```

### Exemple : Authorization Code avec PKCE (SPA)

```javascript
// Frontend Next.js / React
const codeVerifier = generateRandomString(64);
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Rediriger vers Drupal pour l'autorisation
window.location.href = `https://monsite.com/oauth/authorize
  ?response_type=code
  &client_id=${CLIENT_ID}
  &redirect_uri=${encodeURIComponent(REDIRECT_URI)}
  &scope=authenticated
  &code_challenge=${codeChallenge}
  &code_challenge_method=S256`;
```

---

## 4. X-CSRF-Token pour les requêtes d'écriture

```javascript
// Étape 1 : récupérer le token CSRF (si auth cookie / session)
const csrfResponse = await fetch('/session/token');
const csrfToken = await csrfResponse.text();

// Étape 2 : utiliser dans les requêtes write
await fetch('/jsonapi/node/article', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/vnd.api+json',
    'X-CSRF-Token': csrfToken,
    // OU Authorization: Bearer <oauth_token> (pas besoin de X-CSRF-Token avec OAuth)
  },
  credentials: 'include',  // Nécessaire pour l'auth cookie
  body: JSON.stringify({ data: { type: 'node--article', attributes: { title: 'Test' } } }),
});
```

> Avec **OAuth2 Bearer token**, le X-CSRF-Token n'est pas requis.
> Avec **l'authentification par cookie de session**, il est obligatoire pour les POST/PATCH/DELETE.

---

## 5. Rate Limiting JSON:API

```php
// Via le service Flood de Drupal (pour les endpoints d'auth, pas l'API en elle-même)

// Option 1 : Module contrib 'flood_control' + configuration des limites
// Option 2 : Middleware custom pour les endpoints JSON:API sensibles

// src/EventSubscriber/JsonApiRateLimitSubscriber.php
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Drupal\Core\Flood\FloodInterface;

class JsonApiRateLimitSubscriber implements EventSubscriberInterface {

  public function __construct(
    private readonly FloodInterface $flood,
  ) {}

  public function onRequest(RequestEvent $event): void {
    $request = $event->getRequest();

    if (!str_starts_with($request->getPathInfo(), '/jsonapi')) {
      return;
    }

    if ($request->getMethod() === 'POST') {
      if (!$this->flood->isAllowed('jsonapi_write', 60, 60)) {
        throw new TooManyRequestsHttpException(60, 'Trop de requêtes.');
      }
      $this->flood->register('jsonapi_write', 60);
    }
  }

  public static function getSubscribedEvents(): array {
    return [KernelEvents::REQUEST => ['onRequest', 30]];
  }
}
```

---

## 6. Anti-patterns JSON:API sécurité

| ❌ À ne jamais faire | ✅ Bonne pratique | Risque |
|---------------------|------------------|--------|
| Exposer tous les bundles sans ACL | Configurer `hook_jsonapi_*_filter_access` | Fuite de données |
| `allowedOrigins: ['*']` en production | Lister explicitement les origines autorisées | CORS bypass |
| Authentification par cookie sur domaine public | OAuth2 Bearer token pour les SPA | Session hijacking |
| Exposer les champs `mail`, `pass`, `field_api_key` | Désactiver via jsonapi_extras | Data breach |
| Password flow OAuth2 | Client Credentials ou Authorization Code + PKCE | Déprécié, credentials exposés |
| Token OAuth2 en localStorage | Stocker dans httpOnly cookie ou mémoire | XSS token theft |
| Pas de validation de scope OAuth | Configurer les scopes par rôle Drupal | Privilege escalation |
| `/jsonapi` accessible sans HTTPS | HTTPS obligatoire + HSTS | Interception de tokens |

---

## 7. JWT Standalone — JSON Web Tokens sans Simple OAuth

Pour les projets qui ont besoin de JWT mais pas du protocole OAuth2 complet (ex : API interne, microservices, mobile sans authorization code flow).

### Installation

```bash
composer require drupal/jwt
docker compose exec php drush en jwt -y
docker compose exec php drush cr
```

### Configurer la clé JWT

```bash
# Générer une clé HMAC-SHA256 (stocker hors du webroot)
openssl rand -base64 64 > /var/www/private/jwt.key

# Ou générer une paire RSA (recommandé pour RS256)
openssl genpkey -algorithm RSA -out /var/www/private/jwt_private.key -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in /var/www/private/jwt_private.key -out /var/www/private/jwt_public.key
```

```php
// settings.php — configurer le module JWT avec la clé Key module
$config['jwt.config']['algorithm']  = 'RS256';   // ou 'HS256' pour HMAC
$config['jwt.config']['key_id']     = 'jwt_key'; // ID de la clé dans le Key module
```

### 2. Générer un JWT pour un utilisateur

```php
use Drupal\jwt\Authentication\Provider\JwtAuth;
use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

// src/Controller/JwtAuthController.php
class JwtAuthController extends ControllerBase {

  public function __construct(
    private readonly JwtAuth $jwtAuth,
  ) {}

  /**
   * Endpoint de login — retourne un JWT.
   *
   * Route : POST /api/auth/login
   */
  public function login(Request $request): JsonResponse {
    $credentials = json_decode($request->getContent(), TRUE);

    if (empty($credentials['username']) || empty($credentials['password'])) {
      return new JsonResponse(['error' => 'Identifiants manquants.'], 400);
    }

    // Vérifier les credentials via le service auth Drupal
    $uid = \Drupal::service('user.auth')
      ->authenticate($credentials['username'], $credentials['password']);

    if (!$uid) {
      // Enregistrer la tentative échouée pour le rate limiting
      \Drupal::flood()->register('jwt.failed_auth', 3600);
      return new JsonResponse(['error' => 'Identifiants invalides.'], 401);
    }

    // Charger le compte et générer le JWT
    $account = $this->entityTypeManager()->getStorage('user')->load($uid);
    \Drupal::service('current_user')->setAccount($account);

    // generateToken() signe le JWT avec la clé configurée
    $token = $this->jwtAuth->generateToken();

    if (!$token) {
      return new JsonResponse(['error' => 'Impossible de générer le token.'], 500);
    }

    return new JsonResponse([
      'token'      => $token,
      'expires_in' => 3600,
      'token_type' => 'Bearer',
      'uid'        => $uid,
    ]);
  }
}
```

### 3. Utiliser le JWT dans les requêtes frontend

```javascript
// Frontend JavaScript — stocker dans mémoire (pas localStorage pour éviter XSS)
let jwtToken = null;

// Login
async function login(username, password) {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (!res.ok) throw new Error('Authentification échouée');

  const data = await res.json();
  jwtToken = data.token;   // Stocker en mémoire, pas localStorage

  // Programmer le renouvellement avant expiration
  setTimeout(renewToken, (data.expires_in - 60) * 1000);
}

// Requête JSON:API authentifiée avec JWT
async function fetchArticles() {
  const response = await fetch('/jsonapi/node/article', {
    headers: {
      'Authorization': `Bearer ${jwtToken}`,
      'Content-Type': 'application/vnd.api+json',
      'Accept': 'application/vnd.api+json',
    },
  });

  if (response.status === 401) {
    // Token expiré — rediriger vers le login
    jwtToken = null;
    window.location.href = '/login';
    return;
  }

  return response.json();
}
```

### 4. Valider un JWT custom dans un service PHP

```php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Drupal\user\Entity\User;
use Drupal\Core\Entity\EntityTypeManagerInterface;

// Pour les projets sans module drupal/jwt — validation manuelle
class JwtValidatorService {

  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * Valider un JWT et retourner le compte utilisateur associé.
   */
  public function validateToken(string $token): ?\Drupal\Core\Session\AccountInterface {
    $secret = getenv('JWT_SECRET');

    if (!$secret) {
      throw new \RuntimeException('JWT_SECRET non configuré dans les variables d\'environnement.');
    }

    try {
      // Décoder et valider la signature + expiration automatiquement
      $decoded = JWT::decode($token, new Key($secret, 'HS256'));

      if (!isset($decoded->uid)) {
        return NULL;
      }

      /** @var \Drupal\user\UserInterface|null $user */
      $user = $this->entityTypeManager
        ->getStorage('user')
        ->load($decoded->uid);

      // Vérifier que l'utilisateur est actif
      if (!$user || !$user->isActive()) {
        return NULL;
      }

      return $user;

    } catch (ExpiredException $e) {
      // Token expiré — ne pas logger (événement normal)
      return NULL;
    } catch (SignatureInvalidException $e) {
      // Signature invalide — potentielle tentative de manipulation
      \Drupal::logger('mon_module')->warning('JWT : signature invalide détectée.');
      return NULL;
    } catch (\Exception $e) {
      \Drupal::logger('mon_module')->error('JWT validation error : @msg', ['@msg' => $e->getMessage()]);
      return NULL;
    }
  }

  /**
   * Générer un JWT custom (sans module drupal/jwt).
   *
   * @param int $uid     UID de l'utilisateur
   * @param int $ttl     Durée de validité en secondes (défaut : 3600)
   */
  public function generateToken(int $uid, int $ttl = 3600): string {
    $secret = getenv('JWT_SECRET');
    $now    = time();

    $payload = [
      'iss' => \Drupal::request()->getSchemeAndHttpHost(),  // Issuer
      'aud' => \Drupal::request()->getSchemeAndHttpHost(),  // Audience
      'iat' => $now,                                        // Issued At
      'nbf' => $now,                                        // Not Before
      'exp' => $now + $ttl,                                 // Expiration
      'uid' => $uid,
    ];

    return JWT::encode($payload, $secret, 'HS256');
  }
}
```

### 5. Renouvellement de token (Refresh)

```php
// src/Controller/JwtRefreshController.php
class JwtRefreshController extends ControllerBase {

  public function __construct(
    private readonly JwtValidatorService $jwtValidator,
  ) {}

  /**
   * Renouveler un JWT valide (non expiré) avant son expiration.
   *
   * Route : POST /api/auth/refresh
   * Header : Authorization: Bearer <token>
   */
  public function refresh(Request $request): JsonResponse {
    $authHeader = $request->headers->get('Authorization', '');

    if (!str_starts_with($authHeader, 'Bearer ')) {
      return new JsonResponse(['error' => 'Token manquant.'], 401);
    }

    $token   = substr($authHeader, 7);
    $account = $this->jwtValidator->validateToken($token);

    if (!$account) {
      return new JsonResponse(['error' => 'Token invalide ou expiré.'], 401);
    }

    // Générer un nouveau token
    $new_token = $this->jwtValidator->generateToken($account->id());

    return new JsonResponse([
      'token'      => $new_token,
      'expires_in' => 3600,
    ]);
  }
}
```

### 6. Anti-patterns JWT

| ❌ | ✅ | Raison |
|----|----|--------|
| Stocker le JWT dans `localStorage` | Mémoire JavaScript ou `httpOnly` cookie | XSS peut voler `localStorage` |
| JWT sans expiration (`exp` absente) | Toujours définir `exp` (max 1h pour les access tokens) | Token valide indéfiniment si volé |
| Algorithme `none` ou `HS256` avec secret court | `RS256` (clé RSA) ou `HS256` avec secret ≥ 256 bits | Attaque par force brute sur secret court |
| Pas de vérification `iss` / `aud` | Valider `iss` et `aud` dans le payload | Token d'un autre service accepté |
| JWT en GET param dans l'URL | Header `Authorization: Bearer` uniquement | URLs loguées par les proxies/serveurs |
| Secret JWT dans le YAML de config Drupal | `getenv('JWT_SECRET')` via variable d'environnement | Secret versionné dans git |
| Blacklist de tokens en base pour la révocation | Utiliser des refresh tokens courts + révocation par `jti` | Scalabilité : blacklist non scalable en cluster |
