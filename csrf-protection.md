# Protection CSRF (Cross-Site Request Forgery)

## Comprendre l'Attaque CSRF

Un site malveillant fait exécuter une action à ton utilisateur authentifié à son insu. Exemple : un lien sur evil.com qui déclenche une suppression sur ton site Drupal.

```
Utilisateur authentifié → visite evil.com
evil.com → charge <img src="https://monsite.com/node/42/delete">
Drupal → exécute la suppression (la session de l'utilisateur est valide !)
```

La protection CSRF = un token unique par action que le site malveillant ne peut pas connaître.

---

## `_csrf_token: 'TRUE'` dans routing.yml

**Pour toutes les routes GET qui effectuent une action** (pas pour les routes normales de lecture).

```yaml
# ✅ Route d'action avec protection CSRF
mon_module.item_supprimer:
  path: '/mon-module/{item}/supprimer'
  defaults:
    _controller: '\Drupal\mon_module\Controller\ItemController::supprimer'
    _title: 'Supprimer'
  requirements:
    _permission: 'delete mon module items'
    _csrf_token: 'TRUE'    # Drupal valide automatiquement le token
  options:
    parameters:
      item:
        type: entity:mon_module_item

# ❌ Inutile sur une route de lecture
mon_module.liste:
  path: '/mon-module'
  defaults:
    _controller: '...'
  requirements:
    _permission: 'access content'
    # Pas besoin de _csrf_token ici — c'est une lecture
```

Avec `_csrf_token: 'TRUE'`, Drupal vérifie le paramètre `?token=XXX` dans l'URL. Si absent ou invalide → 403.

---

## Générer un Lien avec Token CSRF

```php
use Drupal\Core\Url;

// ✅ Générer l'URL avec token CSRF — query doit être un ARRAY ['token' => '...']
$url = Url::fromRoute('mon_module.item_supprimer', ['item' => $item->id()], [
  'query' => [
    'token' => \Drupal::csrfToken()->get('mon_module.item_supprimer/' . $item->id()),
  ],
]);

// Ou en deux étapes
$url = Url::fromRoute('mon_module.item_supprimer', ['item' => $item->id()]);
$url->setOption('query', [
  'token' => \Drupal::csrfToken()->get($url->getInternalPath()),
]);

// Via un render array link (recommandé — Drupal encode correctement)
$build['supprimer'] = [
  '#type'  => 'link',
  '#title' => $this->t('Supprimer'),
  '#url'   => $url,
];
```

**⚠️ Dans Twig — `path()` ne génère PAS le token CSRF automatiquement :**

```php
// Générer l'URL avec token en PHP (preprocess ou controller)
$variables['delete_url'] = Url::fromRoute(
  'mon_module.item_supprimer',
  ['item' => $item->id()],
  ['query' => ['token' => \Drupal::csrfToken()->get('mon_module.item_supprimer/' . $item->id())]]
)->toString();
```

```twig
{# Utiliser la variable PHP préparée — jamais path() pour les routes CSRF #}
<a href="{{ delete_url }}">Supprimer</a>

{# ❌ FAUX — path() ne connaît pas les requirements CSRF, le token est ABSENT #}
{# <a href="{{ path('mon_module.item_supprimer', {'item': item.id}) }}">Supprimer</a> #}
```

---

## Valider un Token CSRF Manuellement

Pour les routes sans `_csrf_token: 'TRUE'` ou les endpoints custom :

```php
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

public function monAction(Request $request, MonItem $item): Response {
  // Valider le token reçu en paramètre GET
  $token = $request->query->get('token', '');
  $token_value = 'mon_module/supprimer/' . $item->id();

  if (!\Drupal::csrfToken()->validate($token, $token_value)) {
    throw new AccessDeniedHttpException('Token CSRF invalide ou manquant.');
  }

  // Procéder à l'action
  $item->delete();

  return $this->redirect('mon_module.liste');
}
```

---

## Form API — Protection Automatique

**Tous les formulaires Drupal générés via Form API sont automatiquement protégés.** Le champ caché `form_token` est ajouté et validé sans aucun code supplémentaire.

```php
// Drupal gère automatiquement :
// 1. Génération d'un form_token unique dans buildForm()
// 2. Validation dans validateForm() via FormValidator
// 3. Rejet si token invalide ou absent

// Pas de code CSRF nécessaire dans tes FormBase — c'est déjà fait
public function buildForm(array $form, FormStateInterface $form_state): array {
  // form_token est ajouté automatiquement par Drupal
  return $form;
}
```

**Cas où la protection Form API ne suffit pas :**
- Formulaires HTML manuels sans passer par Form API
- Endpoints AJAX custom qui reçoivent des requêtes POST

---

## REST API & JSON:API — Header `X-CSRF-Token`

Pour les requêtes write (POST, PATCH, DELETE) via REST ou JSON:API :

### Étape 1 — Obtenir le token de session

```bash
# Requête GET publique pour obtenir le token CSRF
curl -X GET 'https://mon-site.com/session/token' \
  --cookie 'SESSID=votre-session-id'
# Réponse : "rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```

### Étape 2 — Utiliser le token dans les requêtes write

```bash
# POST — Créer un nœud
curl -X POST 'https://mon-site.com/entity/node?_format=json' \
  -H 'Content-Type: application/json' \
  -H 'X-CSRF-Token: rXXXXXXXXXXXXXXXXXXXXXXXXXX' \
  --cookie 'SESSID=votre-session-id' \
  -d '{
    "type": [{"target_id": "article"}],
    "title": [{"value": "Mon titre"}]
  }'

# PATCH — Modifier un nœud
curl -X PATCH 'https://mon-site.com/node/42?_format=json' \
  -H 'Content-Type: application/json' \
  -H 'X-CSRF-Token: rXXXXXXXXXXXXXXXXXXXXXXXXXX' \
  --cookie 'SESSID=votre-session-id' \
  -d '{"title": [{"value": "Nouveau titre"}]}'

# DELETE
curl -X DELETE 'https://mon-site.com/node/42?_format=json' \
  -H 'X-CSRF-Token: rXXXXXXXXXXXXXXXXXXXXXXXXXX' \
  --cookie 'SESSID=votre-session-id'
```

### En JavaScript (fetch API)

```javascript
// 1. Obtenir le token
const tokenResponse = await fetch('/session/token', { credentials: 'same-origin' });
const csrfToken = await tokenResponse.text();

// 2. Utiliser dans les requêtes write
const response = await fetch('/jsonapi/node/article', {
  method: 'POST',
  credentials: 'same-origin',
  headers: {
    'Content-Type': 'application/vnd.api+json',
    'Accept': 'application/vnd.api+json',
    'X-CSRF-Token': csrfToken,
  },
  body: JSON.stringify({
    data: {
      type: 'node--article',
      attributes: { title: 'Mon article' },
    },
  }),
});
```

---

## Quand CSRF n'est PAS nécessaire

| Situation | CSRF requis ? |
|-----------|--------------|
| Route GET de lecture | ❌ Non |
| Formulaire Form API standard | ✅ Automatique |
| Route GET qui modifie des données | ✅ `_csrf_token: 'TRUE'` |
| REST POST/PATCH/DELETE avec session cookie | ✅ `X-CSRF-Token` header |
| REST avec Basic Auth (credentials dans la requête) | ❌ Non — pas de session |
| REST avec OAuth token (Authorization: Bearer) | ❌ Non — stateless |
| Webhook entrant d'un service externe | ❌ HMAC signature à la place |

---

## Cas Avancé — Token pour les Appels AJAX Drupal

```javascript
// Drupal expose drupalSettings.ajaxPageState et le token dans la page
// Pour les appels AJAX Drupal natifs, le framework gère automatiquement
// Pour les appels AJAX custom :
(function (Drupal, drupalSettings) {
  Drupal.behaviors.monModule = {
    attach: function (context, settings) {
      document.querySelector('.mon-bouton').addEventListener('click', async function() {
        const token = await fetch('/session/token').then(r => r.text());

        const response = await fetch('/mon-module/ajax-action', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'X-CSRF-Token': token,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ id: this.dataset.id }),
        });
      });
    }
  };
})(Drupal, drupalSettings);
```
