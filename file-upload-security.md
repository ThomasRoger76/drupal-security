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

  $detected_mime = \Drupal::service('file.mime_type.guesser')->guess($file->getFileUri());

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
ddev drush php:eval "file_ensure_htaccess();"
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

**SVG dans Drupal :** si tu dois autoriser les SVG, utiliser le module `svg_sanitizer` ou valider manuellement que le SVG ne contient pas de `<script>` ni d'événements JS (`onload`, `onerror`, etc.).

---

## Checklist Sécurité Upload

```bash
# Vérifier la config des champs fichier
ddev drush php:eval "
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
