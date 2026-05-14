# Prévention XSS (Cross-Site Scripting)

## Le Principe : Ne Jamais Faire Confiance à l'Input Utilisateur

XSS = injection de code JavaScript malveillant dans une page web. Conséquences : vol de session, phishing, modification de contenu, propagation automatique.

---

## Twig — La Première Ligne de Défense

**Toute variable affichée avec `{{ var }}` est automatiquement échappée** par Twig via `htmlspecialchars()`. C'est la protection par défaut.

```twig
{# ✅ AUTO-ÉCHAPPÉ — affiche le texte littéralement, jamais de HTML interprété #}
{{ node.title }}
{{ user_input }}
{{ 'Bonjour @name'|t({'@name': user.name}) }}

{# ❌ DANGEREUX — bypasse l'échappement, permet l'injection de scripts #}
{{ variable|raw }}

{# ✅ Seul cas légitime de |raw : HTML généré par votre code (pas par l'utilisateur) #}
{{ drupal_generated_markup|raw }}  {# Seulement si la variable vient de Markup::create() #}
```

### Ce que Twig échappe automatiquement

| Input utilisateur | Rendu HTML sécurisé |
|------------------|---------------------|
| `<script>alert('xss')</script>` | `&lt;script&gt;alert('xss')&lt;/script&gt;` |
| `" onmouseover="alert(1)` | `&quot; onmouseover=&quot;alert(1)` |
| `<img src=x onerror=alert(1)>` | `&lt;img src=x onerror=alert(1)&gt;` |

### Attention : les objets `Markup` passent l'auto-escape

Si une variable est du type `\Drupal\Core\Render\Markup`, Twig ne l'échappe **pas** (elle est marquée comme de confiance). Ne pas créer de `Markup` depuis un input utilisateur.

---

## `Xss::filter()` — Nettoyer du HTML Suspect

À utiliser quand tu dois accepter du HTML de l'utilisateur mais veux bloquer les balises dangereuses.

```php
use Drupal\Component\Utility\Xss;

// Filtrer avec la whitelist par défaut (b, i, em, strong, cite, code, br, p…)
$html_propre = Xss::filter($html_utilisateur);

// Filtrer avec whitelist personnalisée (seulement ces balises)
$strictement_propre = Xss::filter($html_utilisateur, ['b', 'i', 'em', 'strong', 'a']);

// ⚠️ Whitelist vide = supprimer TOUT le HTML (texte brut uniquement)
$texte_brut = Xss::filter($html_utilisateur, []);

// Variante pour contenu admin (whitelist plus large, inclut table, div, etc.)
$admin_html = Xss::filterAdmin($html_depuis_champ_admin);
```

**Quand utiliser `Xss::filter()` :**
- Avant d'insérer du HTML dans la DB sans utiliser les text formats Drupal
- Dans des migrations ou imports de données externes
- Dans des services PHP qui reçoivent du HTML tiers

**À ne pas confondre avec :**
- `check_markup()` qui applique un Text Format Drupal complet (avec filtres configurés)
- `Html::escape()` qui ne filtre pas du HTML mais échappe les caractères spéciaux

---

## `Html::escape()` — Échapper du Texte pour le HTML

À utiliser quand tu construis du HTML en PHP et tu dois intégrer du texte utilisateur.

```php
use Drupal\Component\Utility\Html;

// Échapper pour usage dans le body HTML
$safe_text = Html::escape($user_input);
// '<script>' → '&lt;script&gt;'

// Utilisation dans un attribut HTML (dans un render array)
$build['#attributes']['title'] = Html::escape($user_input);

// Utilisation dans une chaîne HTML construite en PHP
$html = '<div class="user-content">' . Html::escape($user_content) . '</div>';
```

**Ne pas utiliser `Html::escape()` pour :**
- Du HTML que tu veux garder en HTML (utiliser `Xss::filter()`)
- Des attributs dans Twig (Twig les échappe automatiquement)

---

## `#markup` vs `#plain_text` dans les Render Arrays

```php
// ❌ DANGEREUX — si $user_content vient de l'utilisateur, c'est une faille XSS
$build['#markup'] = $user_content;

// ✅ Pour du texte pur provenant d'un utilisateur
$build['#plain_text'] = $user_content;  // Echappé automatiquement par Drupal

// ✅ Pour du HTML généré par votre code (de confiance)
$build['#markup'] = Markup::create('<strong>' . Html::escape($user_input) . '</strong>');

// ✅ Pour du HTML filtré via Xss::filter()
$build['#markup'] = Markup::create(Xss::filter($user_html));
```

**`Markup::create()` = déclarer à Drupal "ce HTML est de confiance".**  
Il est de ta responsabilité de t'assurer que le HTML est bien nettoyé avant de l'envelopper dans `Markup::create()`.

---

## `FormattableMarkup` / `$this->t()` — Messages avec Variables

```php
use Drupal\Component\Render\FormattableMarkup;

// @var → htmlencodé automatiquement (pour valeurs utilisateur)
$message = new FormattableMarkup('Bonjour @name, vous avez @count message(s).', [
  '@name'  => $user->getDisplayName(),  // ← auto-échappé
  '@count' => $count,
]);

// Via t() — identique, @var est toujours échappé
$this->t('Fichier @file supprimé.', ['@file' => $filename]);

// %var → htmlencodé ET mis en <em>
$this->t('Erreur sur le champ %field', ['%field' => $field_name]);

// :var → valeur insérée comme URL sûre dans l'attribut que TU écris (PAS de <a> automatique)
// ⚠️ Valider que l'URL est sûre avant (pas de javascript:)
$this->t('Voir <a href=":url">le résultat</a>', [':url' => $safe_url]);
// :url est substitué dans href — la balise <a> doit être écrite explicitement
```

**`!var` → pas d'échappement du tout → DANGEREUX avec input utilisateur.** Ne jamais utiliser `!var` avec une valeur non fiable.

---

## Text Formats — La Hiérarchie de Confiance

Drupal offre un système de formats de texte pour les champs body/text :

| Format | Balises autorisées | Pour qui | Risque XSS |
|--------|-------------------|---------|-----------|
| `restricted_html` | Très limites | Visiteurs anonymes | ✅ Sûr |
| `basic_html` | b, i, a, ul, li, p, img… | Utilisateurs authentifiés | ✅ Sûr |
| `full_html` | Tout | Admins SEULEMENT | ❌ Dangereux si accessible aux non-admins |
| `plain_text` | Aucune balise | N'importe qui | ✅ Sûr |

**En PHP — appliquer un text format :**

```php
// Appliquer un format de texte à du HTML venant d'un champ
$filtered_text = check_markup($body_value, $body_format);

// Exemple dans un render array
$build['body'] = [
  '#type'       => 'processed_text',
  '#text'       => $node->body->value,
  '#format'     => $node->body->format,
  '#langcode'   => $node->language()->getId(),
];
```

**Règle absolue :** jamais affecter "Full HTML" à un rôle non-admin dans l'interface Drupal (`/admin/config/content/formats`).

---

## Cas Particuliers

### Attributs HTML générés en PHP

```php
use Drupal\Core\Template\Attribute;

// ✅ Utiliser la classe Attribute pour construire des attributs (auto-échappe)
$attributes = new Attribute([
  'class'    => ['mon-element', $dynamic_class],
  'data-id'  => $node->id(),
  'title'    => $user_title,  // ← automatiquement échappé
]);

// Dans un render array
$build['#attributes'] = $attributes->toArray();
```

### JSON dans des attributs `data-*`

```php
// ❌ FAUX — Html::escape() après json_encode casse le JSON (double-encodage des quotes)
// json_encode(['key' => 'val']) → {"key":"val"}
// Html::escape({"key":"val"}) → {&quot;key&quot;:&quot;val&quot;} ← JavaScript ne peut plus parser
$json_data = Html::escape(json_encode(['key' => $user_value]));

// ✅ Correct — JSON_HEX_TAG échappe < et > pour éviter XSS, Drupal encode l'attribut
// JSON_HEX_TAG convertit < en < et > en > — sûr dans le contexte HTML/JSON
$build['#attributes']['data-config'] = json_encode(
  ['key' => $user_value],
  JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
);
// Drupal échappe automatiquement la valeur de l'attribut lors du rendu HTML
```

### Liens générés en PHP

```php
use Drupal\Core\Url;
use Drupal\Core\Link;

// ✅ Drupal échappe automatiquement le texte du lien
$link = Link::fromTextAndUrl(
  $user_title,           // ← texte échappé par Drupal
  Url::fromRoute('...')
)->toString();
```

### `Markup::create()` sur contenu éditeur — Nécessite `Xss::filterAdmin()` d'abord

```php
// ❌ DANGEREUX — contenu d'un titre de menu modifiable par un éditeur non-admin
$title = $menu_item['title'];
if (str_contains($title, '<')) {
  $item['title'] = Markup::create($title);  // XSS si l'éditeur peut insérer du HTML
}

// ✅ Correct — filtrer avec Xss::filterAdmin() avant Markup::create()
use Drupal\Component\Utility\Xss;
use Drupal\Core\Render\Markup;

$title = $menu_item['title'];
if (str_contains($title, '<')) {
  // filterAdmin() = whitelist large mais sans <script>, onmouseover, etc.
  $safe_title = Xss::filterAdmin($title);
  $item['title'] = Markup::create($safe_title);
}
```

**Règle :** si du contenu vient d'un éditeur (pas d'un développeur) :
- Contenu authentifié admin uniquement → `Xss::filterAdmin()` + `Markup::create()`
- Contenu visiteur/éditeur → `Xss::filter()` + `Markup::create()`
- Code interne du développeur → `Markup::create()` direct acceptable

---

### `strip_tags()` — Insuffisant pour les attributs HTML

```php
// ❌ Insuffisant — les attributs dans les balises autorisées peuvent contenir XSS
'#markup' => strip_tags($user_content, '<strong><b><em><i><span>');
// <span onmouseover="alert(1)">texte</span> passe silencieusement !

// ✅ Correct — Xss::filter() retire aussi les attributs dangereux
use Drupal\Component\Utility\Xss;
use Drupal\Core\Render\Markup;

'#markup' => Markup::create(Xss::filter($user_content, ['strong', 'b', 'em', 'i', 'span', 'br']));
```

**Règle :** `strip_tags()` PHP ne nettoie PAS les attributs JS (`onclick`, `onmouseover`, `onerror`). Toujours utiliser `Xss::filter()` pour du HTML utilisateur.

### Text Format `full_html` hardcodé — Risque silencieux

```php
// ❌ DANGEREUX — si 'full_html' n'existe pas, Drupal filtre avec le format par défaut
$node->set('field_body', [
  'value'  => $external_html_content,
  'format' => 'full_html',   // Hardcodé — peut ne pas exister en prod
]);

// ✅ Vérifier que le format existe avant de l'utiliser
use Drupal\filter\Entity\FilterFormat;

$format_id = 'full_html';
if (!FilterFormat::load($format_id)) {
  // Fallback vers un format sûr qui existe systématiquement
  $format_id = filter_fallback_format();
}
$node->set('field_body', ['value' => Xss::filter($external_html_content), 'format' => $format_id]);
```

---

### JSON-LD structuré — Pattern sécurisé

Pour les rich snippets Schema.org générés dynamiquement depuis des champs nœud :

```php
use Drupal\Component\Serialization\Json;

// ✅ Correct — Json::encode échappe les caractères dangereux + #markup acceptable
// car le JSON ne contient pas de HTML interprétable en contexte JSON-LD
$schema = ['@context' => 'https://schema.org', '@type' => 'Event', 'name' => $node->label()];
$variables['event_json_ld'] = Json::encode($schema);

// Dans le template Twig :
// <script type="application/ld+json">{{ event_json_ld|raw }}</script>
// ← |raw acceptable ici car Json::encode échappe les caractères sensibles (<, >, &)
// ← Mais vérifier que node->label() ne contient pas de HTML (utiliser strip_tags ou Xss::filter)
```

### `MessengerInterface` avec HTML

```php
// ✅ Utiliser t() avec placeholders
$this->messenger()->addStatus($this->t(
  'L\'article @title a été supprimé.',
  ['@title' => $node->label()]
));

// ❌ DANGEREUX — HTML direct non nettoyé
$this->messenger()->addStatus('<strong>Fait : ' . $user_input . '</strong>');

// ✅ Si HTML nécessaire
$this->messenger()->addStatus(Markup::create(
  '<strong>Fait : ' . Html::escape($user_input) . '</strong>'
));
```
