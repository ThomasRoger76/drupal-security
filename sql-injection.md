# Prévention Injection SQL

## La Règle Absolue

**Jamais de concaténation de variables dans une requête SQL.** Point.

```php
// ❌ INJECTION SQL CRITIQUE — une seule de ces lignes peut compromettre toute la base
$username = $_GET['user'];  // Valeur : "'; DROP TABLE users; --"
$db->query("SELECT * FROM {users} WHERE name = '$username'");

// ❌ Idem avec sprintf
$db->query(sprintf("SELECT * FROM {nodes} WHERE nid = %d", $nid));  // %d est "safe" pour les entiers mais pas $nid vient de l'utilisateur

// ✅ TOUJOURS utiliser les placeholders
$db->query(
  "SELECT * FROM {users_field_data} WHERE name = :name AND status = :status",
  [':name' => $username, ':status' => 1]
);
```

---

## Drupal Database API — Référence des Méthodes Sécurisées

### SELECT Sécurisé

```php
use Drupal\Core\Database\Connection;

// Injection via constructeur (recommandé dans les classes)
public function __construct(
  private readonly Connection $database,
) {}

// Requête simple avec placeholders
$results = $this->database
  ->query(
    "SELECT nid, title FROM {node_field_data} WHERE type = :type AND status = :status",
    [':type' => $type, ':status' => 1]
  )
  ->fetchAll();

// API Select (plus sûr — pas de SQL littéral)
$results = $this->database
  ->select('node_field_data', 'n')
  ->fields('n', ['nid', 'title', 'created'])
  ->condition('n.type', $type)          // ← paramétré automatiquement
  ->condition('n.status', 1)
  ->orderBy('n.created', 'DESC')
  ->range(0, 10)
  ->execute()
  ->fetchAll();

// fetchAll() → array d'objets stdClass
// fetchAllAssoc('nid') → array indexé par nid
// fetchField() → valeur scalaire unique
// fetchCol() → array d'une seule colonne
// fetchAssoc() → une seule ligne en array associatif
```

### LIKE avec Input Utilisateur — Sécuriser les Wildcards

```php
// ❌ DANGEREUX — l'utilisateur peut injecter % ou _ pour des résultats inattendus
$query->condition('title', '%' . $user_input . '%', 'LIKE');

// ✅ Échapper les caractères spéciaux de LIKE (% et _)
$safe_input = $this->database->escapeLike($user_input);
$query->condition('title', '%' . $safe_input . '%', 'LIKE');

// Exemple complet
$results = $this->database
  ->select('node_field_data', 'n')
  ->fields('n', ['nid', 'title'])
  ->condition('title', '%' . $this->database->escapeLike($user_input) . '%', 'LIKE')
  ->execute()
  ->fetchAll();
```

### IN() Sécurisé

```php
// Tableau de valeurs — automatiquement paramétré
$nids = [1, 2, 3, $user_supplied_nid];

// Avec l'API Select
$results = $this->database
  ->select('node_field_data', 'n')
  ->fields('n')
  ->condition('nid', $nids, 'IN')   // ← paramétré automatiquement
  ->execute()
  ->fetchAll();

// Avec une requête brute
$placeholders = implode(', ', array_fill(0, count($nids), '?'));
// Non recommandé — utiliser l'API Select
```

---

## EntityQuery — La Solution Recommandée pour les Entités Drupal

**Zero SQL direct — toujours paramétré et sécurisé.**

```php
// Requêtes simples
$nids = $this->entityTypeManager
  ->getStorage('node')
  ->getQuery()
  ->condition('type', $type_utilisateur)       // ← safe
  ->condition('title', $titre_utilisateur)     // ← safe
  ->condition('status', 1)
  ->accessCheck(TRUE)                          // ← respecte les droits
  ->execute();

// Conditions OR
$group = $query->orConditionGroup()
  ->condition('title', '%' . $this->database->escapeLike($search) . '%', 'LIKE')
  ->condition('field_tags.entity.name', $search);
$query->condition($group);

// Conditions complexes avec EntityQuery
$query = $this->entityTypeManager->getStorage('node')->getQuery();
$query
  ->condition('type', 'article')
  ->condition('status', 1)
  ->condition('field_categorie', $cat_id_utilisateur)   // ← safe
  ->condition('created', strtotime('-30 days'), '>=')
  ->accessCheck(TRUE)
  ->sort('created', 'DESC')
  ->range(0, $limit);  // $limit validé comme entier au préalable

$nids = $query->execute();
```

---

## ORDER BY Dynamique — La Seule Exception

Les **noms de colonnes** (ORDER BY, GROUP BY) ne peuvent pas être paramétrés dans Drupal comme des valeurs. Il faut une whitelist :

```php
// ❌ DANGEREUX — injection de nom de colonne
$query->orderBy($user_sort_field, $user_sort_direction);

// ✅ Whitelist des colonnes autorisées
$allowed_sort_fields     = ['title', 'created', 'changed', 'nid'];
$allowed_sort_directions = ['ASC', 'DESC'];

$sort_field     = in_array($user_sort_field, $allowed_sort_fields, TRUE)
  ? $user_sort_field
  : 'created';  // valeur par défaut sûre

$sort_direction = in_array(strtoupper($user_sort_dir), $allowed_sort_directions, TRUE)
  ? strtoupper($user_sort_dir)
  : 'DESC';  // valeur par défaut sûre

$query->orderBy($sort_field, $sort_direction);
```

---

## INSERT / UPDATE / DELETE Sécurisés

```php
// INSERT — paramétré automatiquement
$this->database->insert('mon_module_table')
  ->fields([
    'name'       => $user_input_name,    // ← safe
    'value'      => $user_input_value,   // ← safe
    'created_at' => \Drupal::time()->getRequestTime(),
  ])
  ->execute();

// UPDATE — paramétré automatiquement
$this->database->update('mon_module_table')
  ->fields(['value' => $new_value])     // ← safe
  ->condition('uid', $uid)              // ← safe
  ->execute();

// DELETE
$this->database->delete('mon_module_table')
  ->condition('uid', $uid)              // ← safe
  ->condition('created_at', $cutoff, '<')
  ->execute();

// Requête brute DELETE (éviter — utiliser l'API ci-dessus)
$this->database->query(
  "DELETE FROM {mon_module_table} WHERE uid = :uid AND created_at < :cutoff",
  [':uid' => $uid, ':cutoff' => $cutoff]
);
```

---

## Valider les Types Avant Utilisation

Une deuxième couche de défense : toujours valider/caster les types avant les requêtes.

```php
// IDs numériques — caster en entier
$nid = (int) $request->query->get('nid');
if ($nid <= 0) {
  throw new BadRequestHttpException('NID invalide');
}

// Strings — valider la longueur et le format
$username = $request->query->get('name', '');
if (mb_strlen($username) > 255 || !preg_match('/^[a-zA-Z0-9_\-\.]+$/', $username)) {
  throw new BadRequestHttpException('Username invalide');
}

// Listes d'IDs — valider chaque élément
$ids = array_map('intval', explode(',', $request->query->get('ids', '')));
$ids = array_filter($ids, fn($id) => $id > 0);
```

---

## Transactions — Atomicité et Sécurité

```php
// Toujours utiliser des transactions pour les opérations multi-étapes
$transaction = $this->database->startTransaction();
try {
  $this->database->insert('mon_module_main')
    ->fields(['name' => $name, 'uid' => $uid])
    ->execute();

  $this->database->insert('mon_module_log')
    ->fields(['action' => 'created', 'uid' => $uid, 'ts' => time()])
    ->execute();

  // Commit implicite à la fin du bloc try
} catch (\Exception $e) {
  $transaction->rollBack();
  \Drupal::logger('mon_module')->error('Transaction échouée : @msg', [
    '@msg' => $e->getMessage(),
  ]);
  throw $e;
}
```

---

## Checklist Anti-SQL Injection

```php
// ❌ Tous les patterns à bannir dans les code reviews
$db->query("... WHERE id = $id");
$db->query("... WHERE name = '" . $name . "'");
$db->query(sprintf("... WHERE id = %s", $id));
$db->query("... ORDER BY $column");   // ← sans whitelist

// ✅ Patterns corrects
$db->query("... WHERE id = :id", [':id' => $id]);
$db->select('table', 't')->condition('name', $name);
// EntityQuery pour les entités Drupal
// $db->escapeLike() pour les LIKE
// Whitelist pour ORDER BY
```
