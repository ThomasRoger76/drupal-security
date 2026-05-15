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

### Content Security Policy (CSP)

```apache
# CSP strict — adapter selon les ressources utilisées
Header always set Content-Security-Policy "\
  default-src 'self'; \
  script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
  style-src 'self' 'unsafe-inline'; \
  img-src 'self' data: blob:; \
  font-src 'self'; \
  connect-src 'self'; \
  frame-ancestors 'self'; \
  base-uri 'self';"
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
