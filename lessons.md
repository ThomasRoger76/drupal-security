# Leçons — drupal-security

Failles découvertes en audit, code review ou incident réel. Mis à jour après chaque découverte.

---

## Comment ajouter une leçon

Après chaque faille trouvée ou incident :
1. Documenter le symptôme, la cause, la correction, la prévention
2. Ajouter une ligne dans `CHANGELOG.md`
3. Si la faille touche plusieurs projets → envisager une règle hookify

---

## 2026-05-14 — Création du skill

### `{{ var|raw }}` avec input utilisateur — XSS
- **Symptôme :** Scripts JavaScript injectés dans les pages ; vol de sessions ; redirection des utilisateurs
- **Cause :** `|raw` bypasse l'auto-escaping de Twig — permet l'exécution de JS arbitraire
- **Correct :** Supprimer `|raw`. Twig auto-échappe par défaut. Si du HTML est nécessaire : `Xss::filter()` + `Markup::create()`
- **Prévention :** Interdire `|raw` dans les code reviews sauf pour du HTML généré par le code (jamais par l'utilisateur). Ajouter une règle hookify sur `|raw`

### `$db->query("... WHERE name = '$var'")` — SQL Injection
- **Symptôme :** Possibilité d'extraire ou modifier n'importe quelle donnée en DB ; `'OR '1'='1` dans le champ utilisateur passe
- **Cause :** Concaténation directe de variable dans la requête SQL
- **Correct :** `$db->query("... WHERE name = :name", [':name' => $var])`
- **Prévention :** Interdire tout `$db->query(` sans placeholder dans les code reviews. Utiliser EntityQuery pour les entités Drupal

### `$user->id() == 1` pour checker les droits — Bypass potentiel
- **Symptôme :** En cas de réinstallation ou création de Drupal fraîche, l'UID 1 peut être un autre utilisateur
- **Cause :** L'UID 1 est le premier utilisateur créé — dans certains workflows CI/CD, ce n'est pas l'admin réel
- **Correct :** `$user->hasPermission('administer site configuration')`
- **Prévention :** Rejeter systématiquement `->id() == 1` et `hasRole('administrator')` en code review

### Route d'action sans `_csrf_token: 'TRUE'` — CSRF
- **Symptôme :** Un lien externe peut déclencher des actions (suppression, activation) sur le site
- **Cause :** Route GET qui modifie des données sans validation du token CSRF
- **Correct :** Ajouter `_csrf_token: 'TRUE'` dans les `requirements:` de la route
- **Prévention :** Toute route dont le handler modifie des données DOIT avoir `_csrf_token: 'TRUE'`

### Fichiers uploadés dans `public://` avec extension `.php` — RCE
- **Symptôme :** Accès direct à `https://site.com/sites/default/files/shell.php` → exécution de code arbitraire
- **Cause :** Aucune restriction sur l'upload de fichiers PHP dans le schéma public
- **Correct :** (1) Whitelist les extensions dans le champ fichier ; (2) vérifier que `.htaccess` dans `public://` bloque l'exécution PHP
- **Prévention :** Jamais autoriser `.php`, `.phtml`, `.phar` dans les extensions. Vérifier `.htaccess` après chaque déploiement

### Text format "Full HTML" accessible aux éditeurs non-admin — XSS persistent
- **Symptôme :** Un éditeur peut insérer `<script>` dans un article → touche tous les visiteurs
- **Cause :** Le format "Full HTML" n'est pas restreint aux administrateurs
- **Correct :** `/admin/config/content/formats` → "Full HTML" → restreindre aux rôles admin uniquement
- **Prévention :** Security Review module détecte cette configuration. Audit après chaque changement de rôles

### `trusted_host_patterns` non configuré — Host Header Injection
- **Symptôme :** Un attaquant peut injecter un Host: header pour générer des liens malveillants dans les emails de reset de password
- **Cause :** `trusted_host_patterns` absent de `settings.php`
- **Correct :** Ajouter `$settings['trusted_host_patterns'] = ['^monsite\.com$'];` dans settings.php
- **Prévention :** Checklist de déploiement — vérifier trusted_host_patterns. `/admin/reports/status` signale l'absence

### `AccessResult` sans cache — Cache poisoning ou performances dégradées
- **Symptôme :** Tous les utilisateurs voient le même contenu (mauvais cache) ou les pages sont très lentes
- **Cause :** `hook_entity_access()` retourne `AccessResult::allowed()` sans `cachePerUser()` ou `cachePerPermissions()`
- **Correct :** Toujours ajouter la metadata de cache appropriée à l'AccessResult
- **Prévention :** Tout `AccessResult` dans `hook_entity_access()` doit avoir au minimum `cachePerPermissions()` ou `addCacheableDependency()`

### `Markup::create()` sur titre de menu sans `Xss::filterAdmin()` — XSS éditeur
- **Symptôme :** Un éditeur ayant accès à la configuration des menus peut injecter `<img onerror="...">` dans un titre de menu
- **Cause :** `Markup::create($title)` sans nettoyer le HTML au préalable — déclare le HTML "de confiance" sans le vérifier
- **Correct :** `Markup::create(Xss::filterAdmin($title))` — filterAdmin autorise les balises de mise en forme sans XSS
- **Prévention :** Toute variable venant d'un éditeur (pas d'un développeur) doit passer par `Xss::filter()` ou `Xss::filterAdmin()` avant `Markup::create()`

### `full_html` hardcodé dans un setter — Contenu invisible si format absent
- **Symptôme :** Du contenu importé depuis une API externe ne s'affiche pas ou apparaît filtré en production
- **Cause :** `'format' => 'full_html'` hardcodé alors que ce format n'existe pas ou a été désactivé sur l'environnement cible
- **Correct :** Vérifier l'existence du format avec `FilterFormat::load('full_html')` et avoir un fallback sur `filter_fallback_format()`
- **Prévention :** Ne jamais hardcoder un identifiant de text format — le rendre configurable ou vérifier son existence au runtime

### `hook_node_access_records` sans reconstruction — Droits non appliqués
- **Symptôme :** Après installation du module, les nœuds existants sont encore visibles pour tous
- **Cause :** Les grants ne s'appliquent qu'aux nœuds sauvegardés après l'installation — les existants gardent l'ancien état
- **Correct :** `node_access_rebuild()` après l'installation du module ou après changement de logique de grants
- **Prévention :** Toujours déclencher `node_access_rebuild()` dans `hook_install()` et documenter la nécessité de reconstruction

### `path()` Twig sur une route CSRF — Token absent = CSRF possible
- **Symptôme :** Route avec `_csrf_token: 'TRUE'` mais les liens générés via `{{ path(...) }}` n'ont pas de token → accès 403 ou protection absente
- **Cause :** `path()` dans Twig génère l'URL sans connaître les requirements de routing — le token CSRF doit être ajouté manuellement
- **Correct :** Préparer la variable avec token en PHP dans preprocess/controller : `Url::fromRoute(..., [...], ['query' => ['token' => \Drupal::csrfToken()->get(...)]])->toString()`
- **Prévention :** Ne jamais utiliser `{{ path() }}` pour les routes d'action — toujours passer une variable PHP préparée

### Open Redirect via `?destination=` — Phishing
- **Symptôme :** Le lien `https://site.com/user/login?destination=https://evil.com` redirige vers le site malveillant après login
- **Cause :** Usage de la query `destination` sans validation que l'URL est interne
- **Correct :** `UrlHelper::isExternal($destination)` → si vrai, ignorer et rediriger vers `<front>`. Utiliser `\Drupal::service('redirect.destination')->getAsUrl()` qui valide automatiquement
- **Prévention :** Toute redirection basée sur une URL fournie par l'utilisateur doit passer par `UrlHelper::isExternal()` avant usage

### Secrets dans les YAML exportés en git — Data breach
- **Symptôme :** Clé API ou mot de passe visible dans `config/sync/*.yml` → exposé dans le dépôt git
- **Cause :** La Config API exporte toute la config, y compris les champs de type `api_key` non protégés
- **Correct :** Utiliser `$config['config.name']['api_key'] = getenv('API_KEY')` dans `settings.php` pour les secrets. Ajouter `config_ignore` pour les configs avec secrets
- **Prévention :** Avant le premier `drush cex`, identifier et ignorer les configs contenant des secrets
