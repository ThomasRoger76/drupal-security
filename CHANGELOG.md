# Changelog — drupal-security

---

## v1.1 — 2026-05-14

**Bugs corrigés :**
- `csrf-protection.md` : `query` option recevait une string au lieu d'un array `['token' => '...']`
- `csrf-protection.md` : Twig `path()` ne génère PAS le token CSRF — remplacé par pattern PHP correct + avertissement explicite
- `xss-prevention.md` : `:var` décrit incorrectement comme créant une `<a>` automatiquement — corrigé
- `xss-prevention.md` : `Html::escape(json_encode(...))` → double-encodage qui casse le JSON — remplacé par `json_encode(..., JSON_HEX_TAG | JSON_HEX_AMP)`
- `access-control.md` : API JSON:API `setFieldName('')` inexistante — remplacée par approche UI + code correct
- `file-upload-security.md` : Deux APIs d'upload_validators mélangées — séparées avec labels D8/D9 vs D10/D11
- `security-audit.md` : `drush pm:security --security-only` inexistant — remplacé par `--format=json`

**Ajouts sécurité :**
- `access-control.md` : Section Open Redirect avec `UrlHelper::isExternal()` et `redirect.destination` service
- `access-control.md` : Section SSRF avec whitelist de domaines et validation d'URL
- `security-audit.md` : Rate Limiting via service `flood` Drupal core (exemple complet)
- `security-audit.md` : Password Security — `PasswordInterface`, bcrypt, interdiction MD5/SHA1
- `security-audit.md` : CSP & Drupal — nuance `unsafe-inline` obligatoire avec Drupal core
- `security-audit.md` : Session Security — `cookie_secure`, `cookie_httponly`, `cookie_samesite`
- `security-audit.md` : Information Disclosure — masquer X-Generator, CHANGELOG.txt, Stack traces
- `lessons.md` : Leçon `path()` Twig + CSRF token absent
- `lessons.md` : Leçon Open Redirect via `?destination=`

---

## v1.0 — 2026-05-14

**Création initiale**

### Couverture

**`SKILL.md`**
- Les 3 Péchés Capitaux placés en tête (SQL injection, `|raw`, UID==1)
- Quick Decision Table (22 entrées couvrant XSS, CSRF, accès, SQL, uploads, audit)
- Anti-patterns critiques (11 entrées avec l'impact sécurité)
- Table versioning D8→D11 (Twig escaping, CSRF token, JSON:API core, drush pm:security, composer audit)
- Section Auto-Amélioration

**`xss-prevention.md`**
- Twig auto-escaping : mécanisme complet, ce qui est échappé vs ce qui ne l'est pas
- `|raw` : danger et cas légitimes (HTML de confiance uniquement)
- Tableau de transformation des inputs dangereux par Twig
- `Xss::filter()` : whitelist, `filterAdmin()`, whitelist vide
- `Html::escape()` : attributs, body text, chaînes HTML construites en PHP
- `#markup` vs `#plain_text` dans les render arrays
- `Markup::create()` : sémantique et responsabilité
- `FormattableMarkup` / `$this->t()` : `@var`, `%var`, `:var`, `!var` (dangereux)
- Text Formats : Basic HTML, Full HTML, Restricted HTML — tableau de confiance
- `check_markup()` en PHP
- Classe `Attribute` pour les attributs dynamiques
- JSON dans `data-*` attributes
- `MessengerInterface` avec HTML

**`csrf-protection.md`**
- Anatomie de l'attaque CSRF avec exemple
- `_csrf_token: 'TRUE'` dans routing.yml avec exemples commentés
- Générer un lien avec token CSRF automatiquement inclus
- Valider un token CSRF manuellement (code complet)
- Form API : protection automatique expliquée
- REST/JSON:API : `X-CSRF-Token` header — 2 étapes (obtenir + utiliser) avec curl et fetch JS
- Tableau : quand CSRF est requis vs non requis (Basic Auth, OAuth, session cookie)
- Cas avancé : AJAX custom avec récupération du token

**`access-control.md`**
- Règle fondamentale : permission, jamais UID ou rôle en dur (avec exemples des erreurs courantes)
- Contrôle au niveau route : _permission, _entity_access, _custom_access, opérateurs ET (+) et OU (,)
- `AccessResult` : les 3 états (allowed/forbidden/neutral), `forbidden()` l'emporte toujours
- Caching des AccessResult : cachePerUser, cachePerPermissions, addCacheableDependency, setCacheMaxAge
- `hook_entity_access()` : pattern complet avec neutral() pour les cas non concernés
- Node Grants : hook_node_access_records + hook_node_grants — système multi-tenant complet avec gids
- Reconstruction des grants après installation
- JSON:API Security : permissions, désactivation de méthodes, masquage de champs
- Access Checker custom service taggé avec DI
- Audit des permissions via Drush
- `hook_requirements()` pour les vérifications runtime

**`sql-injection.md`**
- Les 3 Péchés SQL : concaténation, sprintf, ORDER BY sans whitelist
- Database API : `query()` avec placeholders, `select()` API, méthodes fetch*
- `escapeLike()` pour les LIKE avec wildcards utilisateur
- IN() sécurisé via l'API Select
- EntityQuery : zero SQL direct — toujours paramétré
- ORDER BY dynamique avec whitelist obligatoire
- INSERT/UPDATE/DELETE sécurisés
- Validation des types (int cast, regex, array_filter)
- Transactions pour l'atomicité
- Checklist anti-SQL injection pour les code reviews

**`file-upload-security.md`**
- Les 4 risques principaux (RCE, XSS via SVG, path traversal, DoS)
- `public://` vs `private://` : tableau comparatif complet (accès, performance, permissions, use cases)
- Configuration de `file_private_path` dans settings.php
- `file_validate_extensions`, `file_validate_size`, `file_validate_image_resolution` dans les formulaires
- Validation MIME type (D10+ FileExtension/FileMimeType validators)
- Validation MIME manuelle via `file.mime_type.guesser`
- `.htaccess` dans `public://` : vérification et régénération
- `hook_file_download()` pour contrôle d'accès aux fichiers private
- Sanitisation des noms de fichiers (translitération, regex)
- Extensions dangereuses à bannir (.php, .phtml, .phar, .exe, .sh, .svg)
- Checklist sécurité upload via Drush

**`security-audit.md`**
- `drush pm:security` : commandes, exemples de sortie, intégration CI/CD
- `composer audit` : commandes, format JSON, intégration GitLab CI
- Sources de veille : tableau complet (drupal.org, email, RSS, Twitter, CI automatisé)
- Activation des notifications Update Manager
- Module Security Review : installation, commandes Drush, tableau des 9 vérifications
- Headers HTTP : X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, CSP
- Via .htaccess, via SecurityKit module, via hook_page_attachments_alter
- Configuration production : error_level, trusted_host_patterns, display_errors, hash_salt, secrets via getenv
- Vérification de la configuration via Drush
- Workflow de mise à jour de sécurité (7 étapes)
- Drupal Steward / WAF : Cloudflare, ModSecurity/OWASP CRS
- Script de checklist avant mise en production

**`lessons.md`**
- 9 leçons pré-remplies avec symptôme/cause/correct/prévention :
  - `|raw` → XSS
  - SQL concatenation → injection
  - `id() == 1` → bypass accès
  - Route sans _csrf_token → CSRF
  - PHP dans public:// → RCE
  - Full HTML pour non-admins → XSS persistant
  - trusted_host_patterns manquant → Host header injection
  - AccessResult sans cache → cache poisoning
  - hook_node_access_records sans rebuild
  - Secrets dans les YAML git

---

## Compatibilité Drupal

| Skill version | Drupal | Notes |
|--------------|--------|-------|
| v1.0 | D8, D9, D10, D11 | JSON:API core depuis D10, drush pm:security depuis D9, composer audit depuis D9 |
