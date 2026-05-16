---
name: security-audit
description: Audit de sécurité automatisé complet d'un projet Drupal — drush pm:security, composer audit, scan du code custom (XSS, SQL injection, CSRF, accès), headers HTTP, configuration production.
---

# Agent : security-audit

## Rôle

Exécuter un audit de sécurité complet et automatisé sur un projet Drupal, produire un rapport priorisé.

## Déclenchement

```bash
/drupal-security-audit              # Audit complet
/drupal-security-audit --quick      # Modules vulnérables uniquement
/drupal-security-audit --code       # Code custom uniquement
/drupal-security-audit --headers    # Headers HTTP uniquement
```

## Pipeline d'exécution

### Étape 1 — Modules vulnérables
```bash
docker compose exec php drush pm:security --format=json
docker compose exec php composer audit --no-dev --format=json
```
**Seuil :** échec si `critical` ou `high` détecté.

### Étape 2 — Scan code custom (XSS/SQL/CSRF)

Scanner `web/modules/custom/` et `web/themes/custom/` pour :

| Pattern dangereux | Règle |
|-------------------|-------|
| `\|raw` dans Twig | ❌ Interdit avec input utilisateur |
| `$db->query("...` + variable | ❌ SQL Injection potentielle |
| `$user->id() == 1` | ❌ Vérification UID fragile |
| `$user->hasRole('administrator')` | ❌ Vérification rôle fragile |
| `#pre_render` sans `TrustedCallbackInterface` | ❌ Callback non trusted |
| `#markup` avec input utilisateur | ❌ XSS potentiel |
| Clé API hardcodée dans PHP | ❌ Secret exposé |

### Étape 3 — Configuration production

Vérifier dans `settings.php` :
- `trusted_host_patterns` configuré
- `error_level` = `hide` en prod
- `config_readonly` = `TRUE` en prod
- `reverse_proxy` si derrière proxy
- `file_private_path` configuré

### Étape 4 — Headers HTTP
```bash
# Obtenir l'URL du site depuis settings.php ou drush
SITE_URL=$(docker compose exec php drush php:eval "echo \Drupal::request()->getSchemeAndHttpHost();" 2>/dev/null | tr -d '\r\n')
echo "Testing: $SITE_URL"

# Vérifier les headers de sécurité HTTP
curl -si "$SITE_URL" | grep -Ei "X-Frame-Options|Content-Security-Policy|X-Content-Type-Options|Strict-Transport-Security|Referrer-Policy|Permissions-Policy"

# Headers attendus en production :
# X-Frame-Options: SAMEORIGIN
# X-Content-Type-Options: nosniff
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Referrer-Policy: strict-origin-when-cross-origin
```

### Étape 5 — Rapport priorisé

```markdown
## Rapport Sécurité — [DATE]

### 🔴 Critique (à corriger immédiatement)
- drupal/paragraphs 1.14 → SA-CONTRIB-2023-003

### 🟠 Élevé (à corriger cette semaine)
- XSS potentiel : web/modules/custom/mon_module/templates/item.html.twig ligne 12

### 🟡 Moyen (à corriger ce sprint)
- trusted_host_patterns manquant dans settings.php

### ✅ OK
- composer audit : 0 CVE
- Headers HTTP : configurés
```
