# Audit & Outils de Veille Sécurité

## `drush pm:security` — Scanner les Modules Vulnérables

```bash
# Vérifier tous les projets Drupal pour des vulnérabilités connues (D9+)
docker compose exec php drush pm:security

# Exemple de sortie
# [critical]  drupal/paragraphs  1.14  SA-CONTRIB-2023-003  Update immediately
# [warning]   drupal/webform     6.1.0  SA-CONTRIB-2023-012  Update soon

# Mettre à jour un module vulnérable
docker compose exec php composer update drupal/paragraphs --with-dependencies
docker compose exec php drush updb -y
docker compose exec php drush cr

# Vérifier avec format JSON (pour CI/CD)
docker compose exec php drush pm:security --format=json
```

**Intégrer dans le pipeline CI/CD :**

```yaml
# .github/workflows/drupal-tests.yml
- name: Check security advisories
  run: |
    vendor/bin/drush pm:security --format=json > security-report.json
    # Échouer si des vulnérabilités critiques sont trouvées
    if grep -q '"critical"' security-report.json; then
      echo "CRITICAL security vulnerabilities found!"
      cat security-report.json
      exit 1
    fi
```

---

## `composer audit` — Scanner les Dépendances PHP (CVE)

```bash
# Vérifier toutes les dépendances Composer pour des CVEs connues
composer audit

# Sans les dépendances de dev (pour la production)
composer audit --no-dev

# Format JSON pour l'intégration CI
composer audit --format=json

# Exemple de sortie
# Found 1 security vulnerability advisory affecting 1 package.
# Package drupal/paragraphs
# CVE-2023-XXXX - Critical - Remote Code Execution via ...
# More info: https://www.drupal.org/sa-contrib-2023-003
```

**Intégrer dans le pipeline :**

```yaml
# GitLab CI
security:composer:
  stage: test
  script:
    - composer audit --no-dev
  allow_failure: false  # Bloquer le pipeline si vulnérabilité
```

---

## Sources de Veille — Ne Jamais Rater une Alerte

| Source | Type | Fréquence |
|--------|------|-----------|
| `drupal.org/security` | Advisories officiels | Mercredi (release day) |
| Abonnement email Drupal Security | Email direct | Immédiat |
| `drupal.org/drupalorg/security-advisories` | RSS | Temps réel |
| `twitter.com/drupalsecurity` | Twitter/X | Immédiat |
| `drush pm:security` en CI | Automatisé | À chaque déploiement |

**Activer les notifications dans l'UI Drupal :**  
`/admin/reports/updates/settings` → configurer l'email de notification + fréquence de vérification

---

## Module Security Review

```bash
# Installer et activer
composer require drupal/security_review
docker compose exec php drush en security_review -y

# Lancer l'audit depuis Drush
docker compose exec php drush secrev

# Lancer avec output détaillé
docker compose exec php drush secrev --log --skipped
```

**Ce que Security Review vérifie :**

| Vérification | Criticité |
|-------------|----------|
| Text format "Full HTML" pour non-admins | 🔴 Critical |
| Upload d'extensions exécutables (.php) autorisé | 🔴 Critical |
| PHP `error_reporting` affiche les erreurs | 🟠 Warning |
| Fichiers `.htaccess` dans `sites/default/files/` | 🟠 Warning |
| `private://` non configuré | 🟠 Warning |
| Rôles avec permissions excessives | 🟠 Warning |
| `update.php` accessible publiquement | 🔴 Critical |
| Sessions PHP sécurisées | 🟡 Info |
| Admin UI exposé sans protection supplémentaire | 🟡 Info |

---

## Headers HTTP de Sécurité

### Via `.htaccess` (recommandé pour Apache)

```apache
# web/.htaccess — ajouter à la section headers existante

# Empêcher le clickjacking
Header always set X-Frame-Options "SAMEORIGIN"

# Empêcher le MIME sniffing
Header always set X-Content-Type-Options "nosniff"

# Force HTTPS (uniquement si SSL est configuré)
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# Contrôler le Referrer
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions Policy (anciennement Feature Policy)
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"

# XSS Protection (legacy mais utile pour les vieux navigateurs)
Header always set X-XSS-Protection "1; mode=block"
```

### Content Security Policy (CSP) — Spécificités Drupal

**⚠️ Drupal impose des contraintes CSP particulières :**
- `'unsafe-inline'` pour **script-src** : Drupal injecte des `drupalSettings` via `<script>` inline
- `'unsafe-inline'` pour **style-src** : CKEditor 5 et quelques modules injectent du CSS inline
- `'unsafe-eval'` : **NE PAS l'activer** — non requis par Drupal core moderne (seulement legacy jQuery)

```apache
# CSP recommandée pour Drupal 10/11
# À adapter selon les modules tiers (analytics, maps, CDN...)
Header always set Content-Security-Policy "\
  default-src 'self'; \
  script-src 'self' 'unsafe-inline'; \
  style-src 'self' 'unsafe-inline'; \
  img-src 'self' data: blob: https:; \
  font-src 'self' data:; \
  connect-src 'self'; \
  frame-ancestors 'self'; \
  base-uri 'self'; \
  form-action 'self';"

# Avec Google Fonts et Analytics (exemple réel) :
# script-src 'self' 'unsafe-inline' https://www.googletagmanager.com;
# style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
# font-src 'self' https://fonts.gstatic.com;
# img-src 'self' data: blob: https://www.google-analytics.com;
```

**Tester la CSP sans la bloquer (Report-Only mode) :**
```apache
# Déployer d'abord en report-only pour voir les violations sans bloquer
Header always set Content-Security-Policy-Report-Only "\
  default-src 'self'; script-src 'self' 'unsafe-inline';"
# → Violations loguées dans la console navigateur
# → Basculer en Content-Security-Policy une fois validé
```

### Via le Module SecurityKit (contrib)

```bash
composer require drupal/seckit
docker compose exec php drush en seckit -y
# Configurer via /admin/config/system/seckit
```

### Via `hook_page_attachments_alter`

```php
function mon_module_page_attachments_alter(array &$attachments): void {
  $attachments['#attached']['http_header'][] = [
    'X-Frame-Options',
    'SAMEORIGIN',
  ];
  $attachments['#attached']['http_header'][] = [
    'X-Content-Type-Options',
    'nosniff',
  ];
}
```

---

## Configuration de Production Sécurisée

### `settings.php` — Paramètres Critiques

```php
// ========================
// SÉCURITÉ PRODUCTION
// ========================

// 1. Masquer les erreurs PHP (JAMAIS afficher en prod)
$config['system.logging']['error_level'] = 'hide';

// 2. Trusted Host Patterns — anti-host-header injection
$settings['trusted_host_patterns'] = [
  '^www\.monsite\.com$',
  '^monsite\.com$',
  '^staging\.monsite\.com$',
];

// 3. Désactiver l'affichage des erreurs PHP
// php.ini ou via settings :
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/drupal-errors.log');

// 4. Hash salt (généré automatiquement, ne pas modifier)
$settings['hash_salt'] = 'HASH_UNIQUE_GENERE_PAR_DRUPAL';

// 5. Ne jamais activer ces options en production
// $settings['rebuild_access'] = FALSE;   // Doit être FALSE
// $settings['skip_permissions_hardening'] = FALSE;  // Doit être FALSE

// 6. Répertoire private
$settings['file_private_path'] = '/var/www/private';

// 7. Secrets — jamais dans les YAML git
$config['smtp.settings']['smtp_password'] = getenv('SMTP_PASSWORD');
$config['mon_module.settings']['api_key']  = getenv('MON_API_KEY');
```

### Vérifier la Configuration de Sécurité

```bash
# Rapport de statut Drupal — vérifier les warnings sécurité
docker compose exec php drush status
docker compose exec php drush php:eval "
  \$requirements = [];
  foreach (\Drupal::moduleHandler()->getImplementations('requirements') as \$module) {
    \$requirements = array_merge(\$requirements, \Drupal::moduleHandler()->invoke(\$module, 'requirements', ['runtime']));
  }
  foreach (\$requirements as \$key => \$req) {
    if (isset(\$req['severity']) && \$req['severity'] >= 1) {
      echo \$key . ': ' . strip_tags(\$req['description'] ?? '') . PHP_EOL;
    }
  }
"

# Ou via l'UI : /admin/reports/status
```

---

## Mises à Jour de Sécurité — Workflow

```bash
# 1. Vérifier les mises à jour disponibles
docker compose exec php drush pm:security
docker compose exec php composer outdated

# 2. Mettre à jour en sécurité
docker compose exec php composer update drupal/core-recommended drupal/core-composer-scaffold --with-dependencies

# 3. Appliquer les updates DB et la config
docker compose exec php drush updb -y
docker compose exec php drush cim -y
docker compose exec php drush cr

# 4. Tester avant de déployer
docker compose exec php drush test:run --types=PHPUnit-Unit mon_module

# 5. Déployer
git add . && git commit -m "security: update core to $(drush core:status --format=json | jq -r '.drupal-version')"
```

---

## Drupal Steward & WAF

**Drupal Steward** : service payant de la Drupal Association — pare-feu applicatif (WAF) spécifique à Drupal.

**Alternatives gratuites/moins chères :**
- **Cloudflare WAF** — règles community Drupal disponibles
- **ModSecurity** — avec le ruleset OWASP Core Rule Set (CRS)
- **AWS WAF** — avec managed rules

**Configuration ModSecurity pour Drupal :**
```apache
# .htaccess ou config Apache
SecRuleEngine On
SecRequestBodyAccess On
# Activer le CRS OWASP
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/rules/*.conf
```

---

## Rate Limiting & Brute Force — Module Flood

Drupal core inclut le service `flood` pour limiter les tentatives répétées :

```php
use Drupal\Core\Flood\FloodInterface;

public function __construct(
  private readonly FloodInterface $flood,
) {}

public function monAction(string $identifier): bool {
  // Limiter à 10 tentatives par heure par IP
  if (!$this->flood->isAllowed('mon_module.action', 10, 3600, $identifier)) {
    throw new TooManyRequestsHttpException(3600, 'Trop de tentatives.');
  }

  // Enregistrer la tentative
  $this->flood->register('mon_module.action', 3600, $identifier);

  // ... logique de l'action

  // Nettoyer en cas de succès
  $this->flood->clear('mon_module.action', $identifier);
  return TRUE;
}
```

**Configuration Drupal core** — limites de connexion :  
`/admin/config/people/accounts` → paramètres de blocage de compte

---

## Password Security — Ne Jamais Stocker en Clair

```php
use Drupal\Core\Password\PasswordInterface;

// Service Drupal pour les mots de passe (bcrypt)
public function __construct(
  private readonly PasswordInterface $password,
) {}

// Hasher un mot de passe
$hash = $this->password->hash($plain_password);

// Vérifier un mot de passe
$is_valid = $this->password->check($plain_password, $stored_hash);

// ❌ Jamais MD5, SHA1, ou stockage en clair
$hash = md5($password);       // INTERDIT
$hash = sha1($password);      // INTERDIT
$hash = base64_encode($password);  // INTERDIT
```

---

## CSP & Drupal — Nuance `unsafe-inline`

```apache
# ⚠️ Drupal requiert 'unsafe-inline' pour fonctionner correctement :
# - drupalSettings est injecté en <script> inline
# - Les styles inline sont utilisés pour le responsive
# - Les behaviors AJAX utilisent des scripts inline

# CSP compatible avec Drupal (minimal fonctionnel)
Header always set Content-Security-Policy "\
  default-src 'self'; \
  script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
  style-src 'self' 'unsafe-inline'; \
  img-src 'self' data: blob: https:; \
  font-src 'self' data:; \
  frame-ancestors 'self';"

# ⚠️ 'unsafe-inline' ne peut pas être éliminé sans modifier le core
```

### CSP avec Nonces — Stratégie plus stricte

Pour éliminer `unsafe-inline`, utiliser des nonces. Drupal supporte ça via le module contrib `csp` (Content Security Policy) :

```bash
composer require drupal/csp
docker compose exec php drush en csp -y
```

```php
// settings.php — configuration CSP via module contrib
// Après installation : /admin/config/system/csp
// Le module génère automatiquement les nonces pour les scripts inline Drupal
```

```apache
# CSP avec nonces (via module drupal/csp) — approche recommandée
# Le module ajoute automatiquement le nonce aux scripts inline générés par Drupal
# Ne pas écrire manuellement la CSP si le module csp est actif
```

**Compromis réaliste :**

| Approche | Sécurité | Compatibilité Drupal | Effort |
|----------|----------|---------------------|--------|
| Sans CSP | ❌ | ✅ | 0 |
| CSP avec `unsafe-inline` | 🟡 Moyen | ✅ | Faible |
| CSP avec nonces (module `csp`) | ✅ Bon | ✅ | Moyen |
| CSP stricte sans nonces | ✅ Élevé | ❌ Casse Drupal | Très élevé |

**Recommandation :** installer `drupal/csp` et utiliser le mode `nonce` — c'est le seul moyen d'avoir une CSP stricte sans casser Drupal core.

---

## Session Security — Configuration PHP

```php
// settings.php — sécuriser les sessions
ini_set('session.cookie_secure', 1);      // HTTPS uniquement
ini_set('session.cookie_httponly', 1);    // Inaccessible au JavaScript
ini_set('session.cookie_samesite', 'Strict');  // Anti-CSRF supplémentaire
ini_set('session.use_strict_mode', 1);    // Rejeter les sessions non initialisées

// Durée de session (en secondes)
ini_set('session.gc_maxlifetime', 86400);  // 24h

// Drupal régénère automatiquement l'ID de session à la connexion (anti-fixation)
// → drupal_session_regenerate() appelé dans UserAuth::authenticate()
```

---

## Information Disclosure — Masquer les Indices Techniques

```apache
# .htaccess — masquer le header révélateur "Server"
ServerTokens Prod
ServerSignature Off

# Masquer le header X-Generator ajouté par Drupal
# Via hook_response_alter() ou module securepages
```

```php
// Supprimer le header X-Generator en production
function mon_module_page_attachments_alter(array &$attachments): void {
  if (!in_array(getenv('APP_ENV'), ['local', 'dev'])) {
    // Supprimer les métas révélant la version Drupal
    foreach ($attachments['#attached']['html_head'] ?? [] as $key => $item) {
      if (isset($item[1]) && str_starts_with($item[1], 'drupal')) {
        unset($attachments['#attached']['html_head'][$key]);
      }
    }
  }
}

// Bloquer l'accès direct à CHANGELOG.txt, README.md, etc.
// Ajouter dans .htaccess :
// <FilesMatch "\.(txt|md|info)$">
//   Require all denied
// </FilesMatch>
```

---

## Checklist de Sécurité Avant Mise en Production

```bash
# Automatiser avec un script de vérification
docker compose exec php drush pm:security             # Modules vulnérables
composer audit --no-dev            # CVE dans les dépendances
docker compose exec php drush secrev                  # Security Review module
docker compose exec php drush php:eval "print \Drupal::config('system.logging')->get('error_level');"  # Doit être 'hide'
grep -r "trusted_host_patterns" web/sites/default/settings.php  # Doit être configuré
ls web/sites/default/files/.htaccess  # Doit exister
curl -I https://monsite.com | grep -E "X-Frame|X-Content|Strict-Transport"  # Headers sécurité
```

---

## RGPD — Droit à l'Effacement et Export des Données

### Vue d'ensemble RGPD

Le Règlement Général sur la Protection des Données (RGPD / GDPR) impose plusieurs obligations aux sites Drupal qui collectent des données personnelles. Les trois principaux droits à implémenter sont : le droit à l'effacement (Art. 17), la portabilité des données (Art. 20), et la transparence du consentement (Directive ePrivacy).

---

### 1. Droit à l'effacement (Right to Erasure — Article 17)

```php
use Drupal\user\UserInterface;
use Drupal\Core\Cache\Cache;

/**
 * Implements hook_user_cancel().
 *
 * Anonymiser les données custom liées à l'utilisateur lors de l'annulation
 * de compte. Appelé AVANT la suppression effective selon la méthode choisie.
 *
 * Méthodes disponibles :
 *   - user_cancel_block            : bloquer le compte
 *   - user_cancel_block_unpublish  : bloquer + dépublier le contenu
 *   - user_cancel_reassign         : réassigner le contenu à l'uid 0
 *   - user_cancel_delete           : supprimer le compte et le contenu
 */
function mon_module_user_cancel(
  array $edit,
  UserInterface $account,
  string $method
): void {
  // Anonymiser les données custom liées à cet utilisateur
  \Drupal::database()->update('mon_module_data')
    ->fields([
      'email' => 'anonymise_' . $account->id() . '@supprime.invalid',
      'name'  => 'Utilisateur supprimé',
      'phone' => '',
      'ip'    => '0.0.0.0',
    ])
    ->condition('uid', $account->id())
    ->execute();

  // Logger l'action (sans données personnelles)
  \Drupal::logger('mon_module')->info(
    'Données anonymisées pour uid @uid via méthode @method.',
    ['@uid' => $account->id(), '@method' => $method]
  );
}

/**
 * Implements hook_ENTITY_TYPE_predelete() pour user.
 *
 * Nettoyer TOUTES les données liées à l'utilisateur avant la suppression
 * définitive. Appelé juste avant que l'entité user soit supprimée.
 */
function mon_module_user_predelete(UserInterface $account): void {
  $uid = $account->id();

  // Supprimer les soumissions de formulaires liées à cet utilisateur
  \Drupal::database()->delete('mon_module_submissions')
    ->condition('uid', $uid)
    ->execute();

  // Supprimer les données de profil étendu
  \Drupal::database()->delete('mon_module_profils')
    ->condition('uid', $uid)
    ->execute();

  // Supprimer les fichiers privés de l'utilisateur
  $files = \Drupal::entityTypeManager()
    ->getStorage('file')
    ->loadByProperties(['uid' => $uid, 'uri' => 'private://%']);

  foreach ($files as $file) {
    $file->delete();
  }

  // Invalider le cache associé
  Cache::invalidateTags(['user:' . $uid, 'mon_module_user:' . $uid]);
}
```

---

### 2. Export des données utilisateur (Right to Data Portability — Article 20)

```php
use Drupal\Core\Controller\ControllerBase;
use Drupal\user\UserInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

// src/Controller/GdprExportController.php
class GdprExportController extends ControllerBase {

  /**
   * Exporter toutes les données personnelles d'un utilisateur.
   *
   * Route : /mon-module/gdpr/export/{user}
   * Requirements : _entity_access: 'user.view' + contrôle que l'uid correspond
   */
  public function exportUserData(UserInterface $user): Response {
    // Vérifier que l'utilisateur ne peut exporter que SES données
    // (sauf admin avec permission 'administer users')
    $current_user = $this->currentUser();
    if ($current_user->id() !== $user->id()
        && !$current_user->hasPermission('administer users')) {
      throw new \Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException();
    }

    $data = [
      'export_date' => date('Y-m-d\TH:i:s\Z'),
      'profil'      => [
        'uid'               => $user->id(),
        'nom_affiche'       => $user->getDisplayName(),
        'email'             => $user->getEmail(),
        'date_inscription'  => date('Y-m-d', $user->getCreatedTime()),
        'derniere_connexion' => $user->getLastLoginTime()
          ? date('Y-m-d\TH:i:s', $user->getLastLoginTime())
          : NULL,
        'langues'           => $user->getPreferredLangcode(),
        'roles'             => array_values($user->getRoles(TRUE)),
      ],
      'soumissions'    => $this->getSubmissions($user),
      'commentaires'   => $this->getComments($user),
      'historique'     => $this->getHistorique($user),
    ];

    $filename = 'mes-donnees-' . $user->id() . '-' . date('Y-m-d') . '.json';
    $json     = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

    $response = new Response($json);
    $response->headers->set('Content-Type', 'application/json; charset=utf-8');
    $response->headers->set('Content-Disposition', 'attachment; filename="' . $filename . '"');
    $response->headers->set('X-Robots-Tag', 'noindex');
    return $response;
  }

  /**
   * @return array<int, array{id: int, date: string, titre: string}>
   */
  private function getSubmissions(UserInterface $user): array {
    $rows = \Drupal::database()
      ->select('mon_module_submissions', 's')
      ->fields('s', ['id', 'created', 'titre'])
      ->condition('uid', $user->id())
      ->orderBy('created', 'DESC')
      ->execute()
      ->fetchAll();

    return array_map(fn($row) => [
      'id'    => (int) $row->id,
      'date'  => date('Y-m-d', $row->created),
      'titre' => $row->titre,
    ], $rows);
  }

  private function getComments(UserInterface $user): array {
    return \Drupal::entityTypeManager()
      ->getStorage('comment')
      ->loadByProperties(['uid' => $user->id()])
      |> array_map(fn($c) => [
        'id'       => $c->id(),
        'date'     => date('Y-m-d', $c->getCreatedTime()),
        'contenu'  => $c->get('comment_body')->value,
        'noeud_id' => $c->getCommentedEntityId(),
      ], $$);
  }

  private function getHistorique(UserInterface $user): array {
    // Exemple : historique de connexion depuis dblog
    return \Drupal::database()
      ->select('watchdog', 'w')
      ->fields('w', ['timestamp', 'message'])
      ->condition('uid', $user->id())
      ->condition('type', 'user')
      ->orderBy('timestamp', 'DESC')
      ->range(0, 100)
      ->execute()
      ->fetchAll(\PDO::FETCH_ASSOC);
  }
}
```

---

### 3. Consentement aux cookies — Module eu_cookie_compliance

```bash
# Installation
composer require drupal/eu_cookie_compliance
docker compose exec php drush en eu_cookie_compliance -y
docker compose exec php drush cr
```

```php
// settings.php — configuration du consentement (opt-in obligatoire RGPD)
$config['eu_cookie_compliance.settings']['popup_enabled']          = TRUE;
$config['eu_cookie_compliance.settings']['method']                 = 'opt_in';   // opt_in = RGPD strict
$config['eu_cookie_compliance.settings']['cookie_lifetime']        = 365;        // jours
$config['eu_cookie_compliance.settings']['popup_position']         = 'bottom';
$config['eu_cookie_compliance.settings']['disagree_do_not_show_ui'] = TRUE;

// Catégories de cookies (opt-in granulaire)
$config['eu_cookie_compliance.settings']['cookie_categories'] = [
  'essential'   => ['label' => 'Essentiels',   'status' => TRUE,  'required' => TRUE],
  'analytics'   => ['label' => 'Analytiques',  'status' => FALSE, 'required' => FALSE],
  'marketing'   => ['label' => 'Marketing',    'status' => FALSE, 'required' => FALSE],
  'preferences' => ['label' => 'Préférences',  'status' => FALSE, 'required' => FALSE],
];
```

```javascript
// Vérifier le consentement en JavaScript avant de charger des scripts tiers
if (typeof Drupal !== 'undefined' && typeof drupalSettings.eu_cookie_compliance !== 'undefined') {
  const hasConsent = drupalSettings.eu_cookie_compliance.currentStatus;

  if (hasConsent === 1 || hasConsent === 2) {
    // L'utilisateur a accepté — charger Google Analytics, etc.
    loadAnalytics();
  }
}
```

---

### 4. Durée de rétention des données — Politique de nettoyage

```php
// settings.php — limiter la rétention des logs Drupal
$config['system.logging']['error_level'] = 'hide';         // Masquer les erreurs en prod
$config['dblog.settings']['row_limit']   = 1000;           // Max 1000 entrées (dblog)

// Mieux : désactiver dblog en prod et utiliser syslog (pas de PII en base)
// $modules_to_disable = ['dblog'];
// $settings['config_exclude_modules'] = ['dblog'];
```

```php
// hook_cron — nettoyer automatiquement les données périmées
use Drupal\Core\Database\Database;

/**
 * Implements hook_cron().
 *
 * Nettoyage RGPD : supprimer les données de plus de 2 ans.
 * Conformément à l'article 5 du RGPD (limitation de la conservation).
 */
function mon_module_cron(): void {
  $retention_days = \Drupal::config('mon_module.settings')->get('retention_days') ?? 730;
  $cutoff = \Drupal::time()->getRequestTime() - ($retention_days * 86400);

  // Supprimer les soumissions anonymes anciennes
  $deleted = \Drupal::database()
    ->delete('mon_module_submissions')
    ->condition('uid', 0)                // Uniquement les soumissions anonymes
    ->condition('created', $cutoff, '<')
    ->execute();

  if ($deleted > 0) {
    \Drupal::logger('mon_module')->info(
      'RGPD cron : @count soumissions anonymes supprimées (> @days jours).',
      ['@count' => $deleted, '@days' => $retention_days]
    );
  }

  // Anonymiser les logs watchdog contenant des emails
  // (préférer syslog en production pour éviter ce problème)
  \Drupal::database()
    ->update('watchdog')
    ->expression('message', "REGEXP_REPLACE(message, '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}', '[email masqué]')")
    ->condition('timestamp', $cutoff, '<')
    ->execute();
}
```

---

### 5. Modules RGPD recommandés

```bash
# Module GDPR complet (audit des champs PII, droit à l'oubli, export)
composer require drupal/gdpr
docker compose exec php drush en gdpr gdpr_fields gdpr_consent -y

# Consentement cookies (bannière, opt-in/opt-out)
composer require drupal/eu_cookie_compliance
docker compose exec php drush en eu_cookie_compliance -y

# Politique de confidentialité (lien obligatoire RGPD)
# Créer un nœud "Politique de confidentialité" et le configurer :
# /admin/config/people/accounts → Privacy Policy page

# Purge des données utilisateur lors de la suppression
composer require drupal/user_data_deletion
docker compose exec php drush en user_data_deletion -y
```

---

### 6. Masquer les PII dans les logs Watchdog

```php
// EventSubscriber pour masquer les données personnelles dans les logs
use Drupal\Core\Logger\RfcLogLevel;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class GdprLogSubscriber implements EventSubscriberInterface {

  public static function getSubscribedEvents(): array {
    return [\Drupal\Core\Logger\LoggerChannel::class => ['onLog', 100]];
  }

  // Ou via hook_watchdog_log() dans .module :
}

/**
 * Implements hook_watchdog_log().
 *
 * Masquer les données personnelles dans les logs avant persistance.
 */
function mon_module_watchdog_log(array $log_entry): void {
  // On ne peut pas modifier ici — utiliser un Logger custom à la place.
  // Voir : \Drupal\Core\Logger\LoggerChannelInterface
}

// Approche recommandée : Logger Decorator
// src/Logger/GdprLogger.php
use Drupal\Core\Logger\RfcLoggerTrait;
use Psr\Log\LoggerInterface;

class GdprLogger implements LoggerInterface {
  use RfcLoggerTrait;

  public function __construct(private readonly LoggerInterface $inner) {}

  public function log($level, $message, array $context = []): void {
    // Masquer les emails dans le message
    $message = preg_replace(
      '/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/',
      '[email masqué]',
      (string) $message
    );
    // Masquer les IPs si nécessaire
    $message = preg_replace('/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/', '[ip masquée]', $message);

    $this->inner->log($level, $message, $context);
  }
}
```

---

### 7. Anti-patterns RGPD

| ❌ | ✅ | Raison |
|----|----|--------|
| Logs avec emails en clair dans watchdog | Hasher/masquer les emails avant persistance (`preg_replace`) | Fuite PII dans les logs — Art. 5 RGPD |
| Durée de rétention illimitée des données | `hook_cron` de nettoyage avec seuil configurable | Obligation RGPD article 5 — limitation conservation |
| Consentement opt-out (pré-coché) | Opt-in explicite pour les cookies non essentiels | Directive ePrivacy + CNIL |
| Exporter les données sans contrôle d'accès | Vérifier `$current_user->id() === $user->id()` | Fuite de données entre utilisateurs |
| `hook_user_cancel` sans anonymiser les données liées | Anonymiser TOUTES les tables custom liées à l'UID | Obligation droit à l'effacement Art. 17 |
| Stocker les logs indéfiniment en base (dblog) | Limiter via `dblog.settings.row_limit` ou désactiver dblog | PII exposées indéfiniment |
| `row_limit: 0` dans dblog.settings | Minimum `row_limit: 1000` avec rotation | 0 = illimité, problème RGPD + performance |
| Données personnelles dans l'URL (GET params) | POST ou identifiants opaques en URL | URLs logguées par les proxies et navigateurs |
