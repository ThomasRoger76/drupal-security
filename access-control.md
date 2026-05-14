# Contrôle d'Accès — Permissions & API

## Règle Fondamentale : Permission, Jamais UID ou Rôle en Dur

```php
// ❌ FAUX — l'UID 1 peut ne pas être l'admin, les rôles peuvent être renommés/supprimés
if ($user->id() == 1) { /* bypass */ }
if ($user->hasRole('administrator')) { /* accès */ }
if (in_array('editor', $user->getRoles())) { /* accès */ }

// ✅ CORRECT — toujours une permission spécifique et nommée
if ($user->hasPermission('administer mon module')) { /* accès */ }
if ($user->hasPermission('edit any article content')) { /* accès */ }
```

---

## Contrôle au Niveau Route

```yaml
# mon_module.routing.yml

# Permission simple (recommandé)
mon_module.admin:
  path: '/admin/config/mon-module'
  requirements:
    _permission: 'administer mon module'

# Plusieurs permissions (ET logique — les deux requises)
mon_module.edition:
  path: '/mon-module/{item}/edit'
  requirements:
    _permission: 'edit mon module items+access administration pages'

# OU logique — une seule suffit
mon_module.view:
  path: '/mon-module/{item}'
  requirements:
    _permission: 'view mon module items,access content'

# Accès basé sur l'entité (plus sûr pour les entités)
mon_module.node_edit:
  path: '/mon-module/{node}/edit'
  requirements:
    _entity_access: 'node.update'   # Vérifie les droits d'édition du nœud spécifique
  options:
    parameters:
      node:
        type: entity:node

# Accès custom (logique complexe)
mon_module.special:
  path: '/mon-module/special'
  requirements:
    _custom_access: '\Drupal\mon_module\Access\MonAccess::check'
    # OU via service taggé (avec DI) :
    # _mon_module_access: 'TRUE'
```

---

## `AccessResult` — Les 3 États et le Caching

```php
use Drupal\Core\Access\AccessResult;

// ALLOWED — accordé explicitement
return AccessResult::allowed();

// FORBIDDEN — refusé explicitement (l'emporte sur ALLOWED)
return AccessResult::forbidden('Raison du refus pour les logs');

// NEUTRAL — aucune opinion, Drupal continue à vérifier d'autres checkers
return AccessResult::neutral();

// Raccourcis conditionnels
return AccessResult::allowedIf($condition);          // allowed si TRUE, neutral si FALSE
return AccessResult::forbiddenIf($condition);        // forbidden si TRUE, neutral si FALSE
return AccessResult::allowedIfHasPermission($account, 'ma.permission');

// ⚠️ forbidden() L'EMPORTE TOUJOURS sur allowed()
// Si un checker retourne forbidden(), même un autre qui retourne allowed() ne passe pas

// CACHING OBLIGATOIRE — sans ça, Drupal cache incorrectement la décision
return AccessResult::allowed()
  ->cachePerUser()                        // Cache différent par utilisateur
  ->cachePerPermissions()                 // Cache différent par set de permissions (plus efficace)
  ->addCacheableDependency($node)         // Invalide si le nœud change
  ->addCacheTags(['node_list'])           // Invalide si n'importe quel nœud change
  ->setCacheMaxAge(0);                    // Ne jamais cacher (pour les décisions très dynamiques)
```

**Règle de caching :** si ta décision dépend de l'utilisateur → `cachePerUser()`. Si elle dépend des permissions → `cachePerPermissions()` (plus efficace que cachePerUser). Si elle dépend d'une entité → `addCacheableDependency($entity)`.

---

## `hook_entity_access()` — Logique Métier d'Accès

```php
// Dans mon_module.module

use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Session\AccountInterface;

function mon_module_entity_access(
  EntityInterface $entity,
  string $operation,
  AccountInterface $account
): AccessResultInterface {

  // Toujours retourner neutral() si on n'a pas d'opinion sur ce type/opération
  if ($entity->getEntityTypeId() !== 'node') {
    return AccessResult::neutral();
  }

  // Contenu "confidentiel" — seulement les membres confirmés
  if ($entity->bundle() === 'confidentiel' && $operation === 'view') {
    return AccessResult::forbiddenIf(
      !$account->hasPermission('voir contenu confidentiel')
    )
    ->addCacheableDependency($entity)
    ->cachePerPermissions();
  }

  // Le propriétaire peut toujours éditer son propre contenu
  if ($operation === 'update' && $entity->getOwnerId() === $account->id()) {
    return AccessResult::allowedIfHasPermission($account, 'edit own ' . $entity->bundle() . ' content')
      ->cachePerUser()
      ->addCacheableDependency($entity);
  }

  return AccessResult::neutral();
}
```

**Différence `hook_entity_access` vs `hook_node_access` :**
- `hook_entity_access` : tous les types d'entités, toutes les opérations
- `hook_node_access` : nœuds uniquement, intégration avec le système de grants

---

## Node Grants — Système Multi-Tenant

Pour les cas complexes où chaque nœud a des règles d'accès différentes (multi-client, groupes, organisations).

```php
// Dans mon_module.module

/**
 * Définir quels "grants" (clés d'accès) s'appliquent à chaque nœud.
 * Appelé lors de l'enregistrement du nœud → stocké en DB (node_access table).
 */
function mon_module_node_access_records(\Drupal\node\NodeInterface $node): array {
  $grants = [];

  if ($node->bundle() === 'article' && !$node->field_organisation->isEmpty()) {
    $org_id = $node->field_organisation->target_id;

    $grants[] = [
      'realm'        => 'mon_module_organisation',
      'gid'          => $org_id,     // Grant ID = identifiant de l'organisation
      'grant_view'   => 1,
      'grant_update' => 0,
      'grant_delete' => 0,
      'priority'     => 0,
      'langcode'     => $node->language()->getId(),
    ];

    // Les éditeurs de l'org peuvent éditer
    $grants[] = [
      'realm'        => 'mon_module_organisation_edit',
      'gid'          => $org_id,
      'grant_view'   => 1,
      'grant_update' => 1,
      'grant_delete' => 1,
      'priority'     => 0,
    ];
  }

  return $grants;
}

/**
 * Définir quels grants l'utilisateur courant possède.
 * Appelé pour chaque requête d'accès aux nœuds.
 */
function mon_module_node_grants(AccountInterface $account, string $op): array {
  $grants = [];

  // Un utilisateur a accès à tous les nœuds de ses organisations
  $org_ids = mon_module_get_user_organisations($account->id());

  if ($op === 'view') {
    $grants['mon_module_organisation'] = $org_ids;
  }

  if ($op === 'update' || $op === 'delete') {
    if ($account->hasPermission('edit organisation content')) {
      $grants['mon_module_organisation_edit'] = $org_ids;
    }
  }

  return $grants;
}
```

**Après modification des grants :** reconstruire les index avec :
```bash
ddev drush php:eval "node_access_rebuild();"
# OU
ddev drush php:eval "\Drupal\node\NodeAccessRebuildBatch::run([]);"
```

---

## JSON:API Security — Limiter l'Exposition

```yaml
# Dans la config JSON:API (D10+ core)
# /admin/config/services/jsonapi

# Désactiver les méthodes non nécessaires par resource type
# Via config/install/jsonapi.resource_type.node--article.yml :
```

```php
// Côté code — vérifier l'accès JSON:API
// JSON:API respecte automatiquement les entity access checks
// Mais pour les champs sensibles, utiliser ResourceTypeRepository

// Exclure un champ de JSON:API — via la configuration UI ou via le code
// UI : /admin/config/services/jsonapi → Resource types → Disable specific fields

// Via code — hook_jsonapi_resource_type_build_alter() :
function mon_module_jsonapi_resource_type_build_alter(array &$resource_types): void {
  if (isset($resource_types['node--article'])) {
    // Marquer le champ comme non-exposé (disabled)
    $resource_type = $resource_types['node--article'];
    $fields = $resource_type->getFields();
    if (isset($fields['field_secret'])) {
      // Créer un nouveau tableau de champs sans le champ secret
      // L'API varie selon la version — utiliser la config UI en priorité
      unset($resource_types['node--article']->getFields()['field_secret']);
    }
  }
}

// Alternative plus fiable : configurer les champs disabled via
// /admin/config/services/jsonapi et exporter avec drush cex
```

**Permissions JSON:API importantes :**
- `access jsonapi resources` — accès général
- Permissions d'entité standard (`view published content`, `edit any article content`)
- Configurer `/admin/config/services/jsonapi` → Read/Write → autoriser seulement les méthodes nécessaires

---

## Access Checker Custom — Service Taggé (Avec DI)

```php
// src/Access/MonAccessCheck.php
namespace Drupal\mon_module\Access;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Routing\Access\AccessInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mon_module\Service\MonService;

final class MonAccessCheck implements AccessInterface {

  public function __construct(
    private readonly MonService $monService,
  ) {}

  public function check(AccountInterface $account): AccessResultInterface {
    $is_eligible = $this->monService->isUserEligible($account->id());

    return AccessResult::allowedIf($is_eligible)
      ->cachePerUser()
      ->setCacheMaxAge(300);  // Cache 5 minutes
  }
}
```

```yaml
# mon_module.services.yml
services:
  mon_module.access_check:
    class: Drupal\mon_module\Access\MonAccessCheck
    arguments: ['@mon_module.mon_service']
    tags:
      - { name: access_check, applies_to: _mon_module_access }
```

```yaml
# Utilisation dans routing.yml
mon_module.route:
  path: '/mon-module/special'
  requirements:
    _mon_module_access: 'TRUE'  # correspond à applies_to: _mon_module_access
```

---

## Open Redirect — Ne Pas Rediriger vers une URL Utilisateur

```php
use Drupal\Component\Utility\UrlHelper;
use Symfony\Component\HttpFoundation\RedirectResponse;

// ❌ DANGEREUX — redirection ouverte vers n'importe quelle URL (phishing)
$destination = $request->query->get('destination');
return new RedirectResponse($destination);

// ✅ Correct — vérifier que la destination est interne
$destination = $request->query->get('destination', '');

// Option 1 : rejeter les URLs externes
if (UrlHelper::isExternal($destination)) {
  $destination = Url::fromRoute('<front>')->toString();
}
return new RedirectResponse($destination);

// Option 2 : utiliser le service Redirect Destination de Drupal
$redirect = \Drupal::service('redirect.destination')->getAsUrl()->toString();
// ← gère automatiquement la validation de la destination
```

**Contexte typique :** formulaires de login, pages d'accès refusé, workflows multi-étapes.

---

## SSRF — Valider les URLs Avant les Requêtes HTTP

```php
use Drupal\Component\Utility\UrlHelper;
use GuzzleHttp\ClientInterface;

// ❌ SSRF — accès réseau interne, AWS metadata (169.254.169.254), etc.
$client->get($request->query->get('url'));

// ✅ Whitelist de domaines + rejet des IPs internes
public function fetchExternalData(string $url): array {
  // 1. Vérifier que c'est une URL valide et externe
  if (!UrlHelper::isValid($url, TRUE) || !UrlHelper::isExternal($url)) {
    throw new \InvalidArgumentException('URL invalide ou non externe');
  }

  // 2. Whitelist de domaines autorisés (si possible)
  $allowed_domains = ['api.example.com', 'cdn.example.com'];
  $host = parse_url($url, PHP_URL_HOST);
  if (!in_array($host, $allowed_domains, TRUE)) {
    throw new \InvalidArgumentException('Domaine non autorisé : ' . $host);
  }

  // 3. Effectuer la requête
  $response = $this->httpClient->get($url, ['timeout' => 10]);
  return json_decode($response->getBody(), TRUE);
}
```

---

## Audit des Permissions — Vérifications Courantes

```bash
# Lister les permissions d'un rôle
ddev drush role:perm:show editor

# Lister les utilisateurs avec un rôle
ddev drush user:role:list editor

# Vérifier qu'aucun rôle anonyme n'a des permissions excessives
ddev drush php:eval "print_r(\Drupal\user\Entity\Role::load('anonymous')->getPermissions());"
```

```php
// Vérifier si la configuration des permissions est sécurisée
function mon_module_requirements(string $phase): array {
  $requirements = [];

  if ($phase === 'runtime') {
    $anon_role = \Drupal\user\Entity\Role::load('anonymous');
    if ($anon_role->hasPermission('access site in maintenance mode')) {
      $requirements['mon_module_anon_permission'] = [
        'title'       => t('Security: Anonymous permissions'),
        'description' => t('Anonymous users should not access site in maintenance mode.'),
        'severity'    => REQUIREMENT_WARNING,
        'value'       => t('Review anonymous role permissions.'),
      ];
    }
  }

  return $requirements;
}
```
