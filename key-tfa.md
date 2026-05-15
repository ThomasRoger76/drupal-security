# Clés API, TFA et Scanning de Sécurité CI/CD

Référence complète pour la gestion des secrets (module Key), la double authentification TOTP et l'automatisation des audits de sécurité dans un pipeline CI/CD Drupal.

---

## Section A — Module Key (`drupal/key`) : Gestion des secrets

### Problème

Stocker des clés API dans `settings.php` en clair est risqué : un `git blame`, une sauvegarde exposée ou un accès au fichier suffit à compromettre toutes vos intégrations tierces. Le module `key` fournit une couche d'abstraction qui découple l'emplacement du secret de son usage dans le code.

### 1. Installation

```bash
composer require drupal/key
docker compose exec php drush en key -y
```

### 2. Créer une clé via l'UI ou drush

```bash
# Via drush — créer une clé de type "Configuration" (stockée chiffrée en DB)
docker compose exec php drush php:eval "
  \$key = \Drupal\key\Entity\Key::create([
    'id' => 'stripe_api_key',
    'label' => 'Stripe API Key',
    'key_type' => 'authentication',
    'key_provider' => 'config',
    'key_input' => 'text_field',
  ]);
  \$key->setKeyValue('sk_live_XXXXXXXXXXXX');
  \$key->save();
  echo 'Clé créée.';
"
```

Via l'UI : `/admin/config/system/keys` → **Ajouter une clé**.

### 3. Utiliser une clé dans un service custom

```php
<?php

namespace Drupal\mon_module\Service;

use Drupal\key\KeyRepositoryInterface;

class StripeService {

  public function __construct(
    private readonly KeyRepositoryInterface $keyRepository,
  ) {}

  private function getApiKey(): string {
    $key = $this->keyRepository->getKey('stripe_api_key');
    if (!$key) {
      throw new \RuntimeException('Clé Stripe non configurée dans le module Key.');
    }
    return $key->getKeyValue();
  }

  public function createPayment(int $amount): array {
    $stripe = new \Stripe\StripeClient($this->getApiKey());
    return $stripe->paymentIntents->create([
      'amount' => $amount,
      'currency' => 'eur',
    ]);
  }

}
```

```yaml
# mon_module.services.yml
services:
  mon_module.stripe_service:
    class: Drupal\mon_module\Service\StripeService
    arguments:
      - '@key.repository'
```

### 4. Key Provider — Variables d'environnement (recommandé en production)

```bash
composer require drupal/key_env
docker compose exec php drush en key_env -y
```

Configurer dans l'UI Key :
- **Key Provider** : `Environment variable`
- **Variable** : `STRIPE_API_KEY`

```bash
# Dans le fichier .env du projet Docker
STRIPE_API_KEY=sk_live_XXXXXXXXXXXX
```

```php
// settings.php — forcer le provider par variable d'environnement
// (utile pour que les environnements de staging/prod ignorent la config DB)
$config['key.key.stripe_api_key']['key_provider'] = 'env';
$config['key.key.stripe_api_key']['key_provider_settings']['env_variable'] = 'STRIPE_API_KEY';
```

```yaml
# docker-compose.yml — injecter la variable dans le container PHP
services:
  php:
    environment:
      STRIPE_API_KEY: ${STRIPE_API_KEY}
```

### 5. Lire une clé depuis un hook ou un controller (sans injection)

```php
// Acceptable dans un contexte procédural (hook, install, etc.)
/** @var \Drupal\key\KeyRepositoryInterface $key_repo */
$key_repo = \Drupal::service('key.repository');
$api_key = $key_repo->getKey('stripe_api_key')?->getKeyValue();
if (!$api_key) {
  \Drupal::logger('mon_module')->error('Clé Stripe introuvable.');
}
```

### 6. Rotation d'une clé sans redéploiement

```bash
# Mettre à jour la valeur d'une clé existante (ex : rotation mensuelle)
docker compose exec php drush php:eval "
  \$key = \Drupal\key\Entity\Key::load('stripe_api_key');
  \$key->setKeyValue('sk_live_NOUVELLE_VALEUR');
  \$key->save();
  echo 'Clé mise à jour.';
"
# Ou simplement changer la variable d'environnement et redémarrer le container
```

### 7. Comparaison des approches de stockage de secrets

| Approche | Sécurité | Coût | Idéal pour |
|----------|----------|------|------------|
| `settings.php` en clair | ❌ | 0 | Jamais |
| `$config['module']['api_key']` dans `settings.php` | 🟡 | 0 | Dev / staging |
| Key module + DB chiffrée | 🟡 | 0 | Petits projets |
| Key module + variable d'environnement | ✅ | 0 | Production standard |
| Key module + HashiCorp Vault | ✅✅ | Élevé | Enterprise / multisite |

### 8. Anti-patterns

- **Clés API dans `config/sync/` YAML** : git expose le secret à tous les contributeurs
- **Clés hardcodées dans le code PHP** : impossible de les faire tourner sans déploiement
- **`getenv()` direct** sans le module Key : aucune rotation possible, aucune abstraction de source

---

## Section B — TFA (Two-Factor Authentication) avec TOTP

### 1. Installation

```bash
composer require drupal/tfa drupal/tfa_basic_plugins drupal/real_aes
docker compose exec php drush en tfa tfa_basic_plugins real_aes -y
```

Le module `real_aes` fournit le profil de chiffrement requis par TFA pour protéger les seeds TOTP en base de données.

### 2. Créer un profil de chiffrement (requis par TFA)

```bash
# Créer une clé AES-256 pour le chiffrement TFA
docker compose exec php drush php:eval "
  \$key = \Drupal\key\Entity\Key::create([
    'id' => 'tfa_encryption_key',
    'label' => 'TFA Encryption Key',
    'key_type' => 'encryption',
    'key_provider' => 'env',
    'key_provider_settings' => ['env_variable' => 'TFA_ENCRYPTION_KEY'],
    'key_input' => 'none',
  ]);
  \$key->save();
  echo 'Clé TFA créée.';
"
```

```bash
# Générer une clé AES-256 aléatoire (32 octets en base64)
docker compose exec php php -r "echo base64_encode(random_bytes(32));"
# → Coller la valeur dans TFA_ENCRYPTION_KEY dans .env
```

### 3. Configuration TOTP (Google Authenticator / Aegis / Authy)

```php
// settings.php — configuration du profil de chiffrement TFA
$settings['tfa_basic_secret_name_prefix'] = 'tfa_totp_seed_';
$config['encrypt.profile.tfa_encryption']['encryption_key'] = 'tfa_encryption_key';
```

Configuration UI : `/admin/config/people/tfa`
- **Plugin TFA** : TOTP (Time-based One-Time Password)
- **Profil de chiffrement** : `tfa_encryption`
- **Période de grâce** : 7 jours (permet à l'utilisateur de configurer son appli avant l'obligation)

### 4. Forcer le TFA pour certains rôles

```php
// Via l'UI TFA → "Rôles obligatoires" : cocher administrator, editor
// Ou par settings.php pour forcer sans passer par l'UI
$config['tfa.settings']['enabled'] = TRUE;
$config['tfa.settings']['required_roles']['administrator'] = 'administrator';
$config['tfa.settings']['required_roles']['editor'] = 'editor';
$config['tfa.settings']['grace_period'] = 604800; // 7 jours en secondes
```

### 5. Vérifier programmatiquement si TFA est actif pour un utilisateur

```php
use Drupal\Core\Session\AccountInterface;

/**
 * Vérifie si le TFA est configuré pour un compte utilisateur donné.
 */
function mon_module_est_tfa_actif(AccountInterface $account): bool {
  $tfa_settings = \Drupal::config('tfa.settings');
  if (!$tfa_settings->get('enabled')) {
    return FALSE;
  }
  // Vérifier si l'utilisateur a finalisé sa configuration TOTP
  $user_data = \Drupal::service('user.data')->get(
    'tfa',
    $account->id(),
    'tfa_totp_seed'
  );
  return !empty($user_data);
}
```

### 6. Réinitialiser le TFA d'un utilisateur (support)

```bash
# Supprimer le seed TOTP d'un utilisateur (force la reconfiguration)
docker compose exec php drush php:eval "
  \$uid = 42; // UID de l'utilisateur
  \Drupal::service('user.data')->delete('tfa', \$uid, 'tfa_totp_seed');
  \Drupal::service('user.data')->delete('tfa', \$uid, 'tfa_recovery_codes');
  echo 'TFA réinitialisé pour l\'utilisateur ' . \$uid;
"
```

---

## Section C — Scanning de sécurité automatisé en CI/CD

### 1. Trivy — Scan des vulnérabilités des images Docker

```yaml
# .gitlab-ci.yml — job de scan des images Docker
security:trivy:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy image
        --exit-code 1
        --severity HIGH,CRITICAL
        --format table
        ${CI_REGISTRY_IMAGE}/drupal-php:${CI_COMMIT_SHA}
  allow_failure: false
  artifacts:
    when: always
    reports:
      junit: trivy-report.xml
```

```bash
# Lancer manuellement en local pour tester
docker run --rm aquasec/trivy:latest image \
  --severity HIGH,CRITICAL \
  monregistre/drupal-php:latest
```

### 2. `composer audit` et `drush pm:security` dans le pipeline

```yaml
# .gitlab-ci.yml — job d'audit des dépendances PHP
security:composer:
  stage: security
  script:
    # Audit Composer (PSA — PHP Security Advisories)
    - docker compose exec php composer audit --no-dev --format=plain
    # Audit des modules Drupal (advisories drupal.org)
    - docker compose exec php drush pm:security --format=json > security-report.json
    # Échouer si une CVE critique est détectée
    - |
      if grep -q '"severity":"critical"' security-report.json; then
        echo "ERREUR : CVE critique détectée dans les modules Drupal."
        cat security-report.json
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - security-report.json
```

```bash
# Vérification rapide en local
docker compose exec php composer audit
docker compose exec php drush pm:security
```

### 3. OWASP Dependency-Check (analyse approfondie des dépendances)

```yaml
# .gitlab-ci.yml — scan OWASP pour les modules custom
security:owasp:
  stage: security
  image: owasp/dependency-check:latest
  variables:
    # Cache la base NVD pour ne pas la retélécharger à chaque pipeline
    NVD_CACHE: ${CI_PROJECT_DIR}/.owasp-cache
  cache:
    key: owasp-nvd-cache
    paths:
      - .owasp-cache/
  script:
    - /usr/share/dependency-check/bin/dependency-check.sh
        --project "Mon Projet Drupal"
        --scan web/modules/custom
        --format JSON
        --format HTML
        --failOnCVSS 7
        --data ${NVD_CACHE}
  artifacts:
    when: always
    paths:
      - dependency-check-report.html
      - dependency-check-report.json
```

### 4. Security Headers — Vérification post-déploiement

```bash
# Vérifier la présence des headers de sécurité après un déploiement
curl -si https://monsite.com/user/login \
  | grep -E "X-Frame-Options|Content-Security-Policy|X-Content-Type-Options|Strict-Transport-Security|Referrer-Policy"

# Résultat attendu :
# X-Frame-Options: SAMEORIGIN
# X-Content-Type-Options: nosniff
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Referrer-Policy: strict-origin-when-cross-origin
```

```yaml
# .gitlab-ci.yml — job de vérification des headers
security:headers:
  stage: verify
  needs: [deploy]
  script:
    - |
      MISSING=""
      for HEADER in "X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security"; do
        if ! curl -si ${SITE_URL} | grep -qi "${HEADER}"; then
          MISSING="${MISSING} ${HEADER}"
        fi
      done
      if [ -n "${MISSING}" ]; then
        echo "ERREUR : Headers manquants :${MISSING}"
        exit 1
      fi
      echo "Tous les headers de sécurité sont présents."
```

### 5. Drush Security Check complet en une commande

```bash
# Rapport de sécurité complet avant déploiement
docker compose exec php bash -c "
  echo '=== composer audit ===' &&
  composer audit --no-dev &&
  echo '=== drush pm:security ===' &&
  drush pm:security &&
  echo '=== drush core:requirements (sécurité) ===' &&
  drush core:requirements --severity=2 --filter=security
"
```

---

## Anti-Patterns Sécurité Secrets + TFA

| ❌ À ne jamais faire | ✅ Bonne pratique | Impact |
|---------------------|------------------|--------|
| Clés API dans `settings.php` en clair | Module `key` + variable d'environnement | Secret leak |
| Clés API dans les YAML `config/sync/` | Module `key` (hors git) | Fuite dans git |
| `getenv('STRIPE_KEY')` direct dans le code | `$keyRepo->getKey('stripe_api_key')` | Impossible à faire tourner |
| TFA facultatif pour les admins | TFA obligatoire pour `administrator` et `editor` | Compromission de compte |
| Seed TFA en clair en DB | `real_aes` + clé de chiffrement dédiée | Extraction de seed |
| Aucun scan CI sur les images Docker | Trivy `--severity HIGH,CRITICAL` | CVE en production |

## Voir aussi

- `security-audit.md` — Headers HTTP, Security Review module, drush pm:security
- `jsonapi-oauth.md` — OAuth2, Simple OAuth, CORS
- `drupal-config/environment-overrides.md` — `$config[]` overrides dans settings.php
