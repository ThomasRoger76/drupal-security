---
name: drupal-security
description: Use when preventing XSS in Drupal (Twig auto-escaping, Xss::filter, Html::escape, #markup vs #plain_text), implementing CSRF protection (_csrf_token routing, X-CSRF-Token header for REST), configuring access control (hook_entity_access, node grants, AccessResult), preventing SQL injection (Database placeholders, EntityQuery, escapeLike), securing file uploads (public vs private filesystem, extension validation), auditing Drupal security (drush pm:security, Security Review module, HTTP security headers, OWASP Dependency-Check), implementing OAuth2 or JWT authentication, managing API keys with the Key module, configuring Two-Factor Authentication (TFA), implementing RGPD/GDPR compliance (right to erasure, data portability, cookie consent), preventing Open Redirect attacks, or scanning Docker images for CVE with Trivy in Drupal 8-11+
---

# Drupal Security — Référence Complète

## Overview

Référentiel complet de la sécurité Drupal 8-11+ : XSS, CSRF, contrôle d'accès, injection SQL, uploads, audit. Ce skill couvre les vulnérabilités les plus fréquentes et comment les prévenir.

## 🛑 Les 3 Péchés Capitaux — À NE JAMAIS FAIRE

> **1. Concaténer des variables dans une requête SQL**
> ```php
> // ❌ FAILLE SQL INJECTION CRITIQUE
> $db->query("SELECT * FROM {users} WHERE name = '$username'");
> // ✅ Toujours utiliser les placeholders ou EntityQuery
> $db->query("SELECT * FROM {users_field_data} WHERE name = :name", [':name' => $username]);
> ```

> **2. Afficher une variable utilisateur avec `|raw` dans Twig**
> ```twig
> {# ❌ PORTE OUVERTE AU XSS — exécution de scripts arbitraires #}
> {{ variable_utilisateur|raw }}
> {# ✅ Twig auto-escape — toujours laisser Twig faire son travail #}
> {{ variable_utilisateur }}
> ```

> **3. Vérifier les droits par ID d'utilisateur ou nom de rôle en dur**
> ```php
> // ❌ FAUX — l'UID 1 peut changer, les rôles peuvent être renommés
> if ($user->id() == 1) { /* ... */ }
> if ($user->hasRole('administrator')) { /* ... */ }
> // ✅ Toujours vérifier une permission spécifique
> if ($user->hasPermission('administer mon module')) { /* ... */ }
> ```

---

## Quick Decision Table

| Besoin | Outil | Référence |
|--------|-------|-----------|
| Afficher du texte utilisateur de manière sûre en Twig | Auto-escape Twig (par défaut) | [xss-prevention.md](xss-prevention.md) |
| Autoriser certaines balises HTML, bloquer le reste | `Xss::filter($html, ['b', 'i'])` | [xss-prevention.md](xss-prevention.md) |
| Nettoyer pour attribut HTML ou texte pur | `Html::escape($input)` | [xss-prevention.md](xss-prevention.md) |
| Afficher du HTML de confiance dans un render array | `#markup => Markup::create($html)` | [xss-prevention.md](xss-prevention.md) |
| Texte utilisateur sans HTML dans un render array | `#plain_text => $user_input` | [xss-prevention.md](xss-prevention.md) |
| Appliquer un format de texte Drupal (Basic HTML…) | `check_markup($text, $format_id)` | [xss-prevention.md](xss-prevention.md) |
| Protéger une route d'action (suppression, activation…) | `_csrf_token: 'TRUE'` dans routing.yml | [csrf-protection.md](csrf-protection.md) |
| Appel REST/JSON:API write depuis JS | Header `X-CSRF-Token` | [csrf-protection.md](csrf-protection.md) |
| Générer/valider un token CSRF manuellement | `\Drupal::csrfToken()` | [csrf-protection.md](csrf-protection.md) |
| Contrôler l'accès à une route | `_permission:` / `_custom_access:` | [access-control.md](access-control.md) |
| Bloquer l'accès à des entités selon logique métier | `hook_entity_access()` | [access-control.md](access-control.md) |
| Accès multi-tenant par groupe/organisation | `hook_node_access_records()` | [access-control.md](access-control.md) |
| Requête SQL sécurisée avec input utilisateur | Placeholders `:name` ou EntityQuery | [sql-injection.md](sql-injection.md) |
| LIKE sécurisé avec wildcard utilisateur | `$db->escapeLike($input)` | [sql-injection.md](sql-injection.md) |
| ORDER BY dynamique sécurisé | Whitelist des colonnes autorisées | [sql-injection.md](sql-injection.md) |
| Restreindre les types de fichiers uploadés | `file_validate_extensions()` | [file-upload-security.md](file-upload-security.md) |
| Stocker des fichiers confidentiels | Schéma `private://` + `settings.php` | [file-upload-security.md](file-upload-security.md) |
| Scanner les modules vulnérables | `drush pm:security` | [security-audit.md](security-audit.md) |
| Scanner les dépendances PHP (CVE) | `composer audit` | [security-audit.md](security-audit.md) |
| Ajouter des headers HTTP de sécurité | `.htaccess` / `hook_page_attachments_alter` | [security-audit.md](security-audit.md) |
| Audit automatisé des vulnérabilités Drupal | Module Security Review | [security-audit.md](security-audit.md) |
| Sécuriser l'accès JSON:API par rôle | `hook_jsonapi_ENTITY_TYPE_filter_access` | [jsonapi-oauth.md](jsonapi-oauth.md) |
| Configurer CORS pour frontend découplé | `cors.config:` dans services.yml | [jsonapi-oauth.md](jsonapi-oauth.md) |
| Authentification API (OAuth2) | Simple OAuth module | [jsonapi-oauth.md](jsonapi-oauth.md) |
| TrustedCallbackInterface pour callbacks | Implémenter l'interface | [xss-prevention.md](xss-prevention.md) |
| Exclure des champs sensibles de JSON:API | jsonapi_extras ou hooks | [jsonapi-oauth.md](jsonapi-oauth.md) |
| Stocker une clé API sans la mettre dans settings.php | Key module (`drupal/key`) | [key-tfa.md](key-tfa.md) |
| Lire une clé depuis une variable d'environnement Docker | Key module + `key_env` provider | [key-tfa.md](key-tfa.md) |
| Faire tourner une clé API sans redéploiement | `drush php:eval` + `$key->setKeyValue()` | [key-tfa.md](key-tfa.md) |
| Activer la double authentification (TOTP) | Module `drupal/tfa` + `drupal/real_aes` | [key-tfa.md](key-tfa.md) |
| Forcer le TFA pour certains rôles (admins, editors) | Config `tfa.settings` + rôles obligatoires | [key-tfa.md](key-tfa.md) |
| Vérifier si TFA est configuré pour un utilisateur | `user.data` service + clé `tfa_totp_seed` | [key-tfa.md](key-tfa.md) |
| Scanner les images Docker pour CVE | Trivy `--severity HIGH,CRITICAL` en GitLab CI | [key-tfa.md](key-tfa.md) |
| Scanner les dépendances Composer pour CVE | `composer audit` + `drush pm:security` en CI | [key-tfa.md](key-tfa.md) |
| Scan OWASP des modules custom | OWASP Dependency-Check `--failOnCVSS 7` | [key-tfa.md](key-tfa.md) |
| Vérifier les headers de sécurité après déploiement | `curl -si` + grep des headers attendus | [key-tfa.md](key-tfa.md) |
| Droit à l'effacement RGPD (Art. 17) | `hook_user_cancel` + `hook_user_predelete` | [security-audit.md](security-audit.md) |
| Export des données utilisateur (portabilité Art. 20) | Controller JSON + vérification `current_user->id()` | [security-audit.md](security-audit.md) |
| Consentement cookies RGPD (opt-in) | Module `eu_cookie_compliance` + `method: opt_in` | [security-audit.md](security-audit.md) |
| Nettoyage automatique des données périmées | `hook_cron` avec seuil de rétention configurable | [security-audit.md](security-audit.md) |
| Masquer les PII dans les logs watchdog | Logger Decorator + `preg_replace` sur emails/IPs | [security-audit.md](security-audit.md) |
| Authentification JWT sans OAuth2 | Module `drupal/jwt` + `JwtAuth::generateToken()` | [jsonapi-oauth.md](jsonapi-oauth.md) |
| Valider un JWT custom (sans module contrib) | `Firebase\JWT\JWT::decode()` + vérif `uid` + `isActive()` | [jsonapi-oauth.md](jsonapi-oauth.md) |
| Renouvellement de token JWT | Endpoint `/api/auth/refresh` + validation du token existant | [jsonapi-oauth.md](jsonapi-oauth.md) |
| Prévenir un Open Redirect via `?destination=` | `UrlHelper::isExternal()` + `redirect.destination` service | [access-control.md](access-control.md) |
| Rate limiting / protection brute force | Service `flood` core + `\Drupal::flood()->isAllowed()` | [security-audit.md](security-audit.md) |

## Anti-Patterns Critiques

| ❌ À ne jamais faire | ✅ Bonne pratique | Impact |
|---------------------|------------------|--------|
| `{{ var\|raw }}` avec input utilisateur | `{{ var }}` (auto-escape) | XSS |
| `$db->query("... WHERE uid = $uid")` | Placeholders `:uid` | SQL Injection |
| `$user->id() == 1` | `$user->hasPermission('...')` | Bypass contrôle accès |
| `$user->hasRole('administrator')` | `hasPermission()` spécifique | Contournement |
| `#markup` avec input utilisateur non nettoyé | `#plain_text` ou `Markup::create()` | XSS |
| `public://` pour fichiers confidentiels | `private://` + vérification des droits | Data breach |
| Route d'action sans `_csrf_token: 'TRUE'` | Toujours pour les routes GET qui modifient | CSRF |
| Text format "Full HTML" pour non-admins | "Basic HTML" ou "Restricted HTML" | XSS |
| Secrets (clés API) dans les YAML de config | `settings.php` ou variables d'env | Secret leak |
| `error_level` à `verbose` en production | `hide` en production | Info disclosure |
| `trusted_host_patterns` non configuré | Toujours configurer en production | Host header injection |

## Évolution par Version Majeure

| Feature | D8 | D9 | D10 | D11 |
|---------|----|----|-----|-----|
| Twig auto-escaping | ✅ | ✅ | ✅ | ✅ |
| `_csrf_token: 'TRUE'` routing | ✅ | ✅ | ✅ | ✅ |
| `Xss::filter()` / `Html::escape()` | ✅ | ✅ | ✅ | ✅ |
| `AccessResult` avec cache | ✅ | ✅ | ✅ | ✅ |
| JSON:API (core) | contrib | contrib | ✅ core | ✅ core |
| `drush pm:security` | ❌ | ✅ | ✅ | ✅ |
| `composer audit` | ❌ | ✅ | ✅ | ✅ |
| `trusted_host_patterns` | ✅ | ✅ | ✅ | ✅ |
| `private://` file system | ✅ | ✅ | ✅ | ✅ |
| Security Advisories email | ✅ | ✅ | ✅ | ✅ |

## Auto-Amélioration

- **[lessons.md](lessons.md)** — Failles trouvées en audit ou projet réel.
- **[CHANGELOG.md](CHANGELOG.md)** — Historique des versions (v1.0 courante).

## Complémentarité avec les Skills Sécurité Génériques

> Ce skill est **différent** du skill `security-review` générique.

| Skill | Rôle |
|-------|------|
| `security-review` | **Auditer** le code pour des vulnérabilités (code review générique) |
| **`drupal-security`** | **Implémenter** la sécurité avec les APIs Drupal spécifiques (Twig auto-escape, EntityQuery placeholders, AccessResult avec cache, `hook_entity_access`, `trusted_host_patterns`) |

**Workflow :** `security-review` détecte un problème d'accès → `drupal-security` explique comment le corriger avec `AccessResult::forbidden()->cachePerPermissions()` ou `hook_entity_access()`.

---

## See Also

- `drupal-core` — Permissions, routes, access checks côté module
- `drupal-config` — Secrets dans settings.php vs YAML exportable
- `drupal-testing` — Tester les contrôles d'accès (Functional tests)
- `drush` — `drush pm:security`, mises à jour de sécurité
