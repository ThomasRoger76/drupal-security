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
