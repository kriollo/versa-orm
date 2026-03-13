# Filtros WHERE Avanzados

Los filtros WHERE te permiten crear condiciones complejas para seleccionar exactamente los datos que necesitas. VersaORM ofrece múltiples operadores y formas de combinar condiciones.

## Conceptos Clave

- **Condiciones múlt**: Combinar varios WHERE con AND/OR
- **Operadores especiales**: LIKE, IN, BETWEEN, IS NULL
- **Agrupación**: Usar paréntesis para agrupar condiciones lógicas
- **Parámetros seguros**: Protección automática contra SQL injection

## Condiciones múltiples con AND

### Ejemplo básico con múltiples WHERE

```php
// Usuarios activos mayores de 18 años
$usuarios = $orm->table('users')
    ->where('active', '=', true)
    ->where('age', '>', 18)
    ->getAll();

echo "Usuarios encontrados: " . count($usuarios) . "\n";
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE active = 1 AND age > 18;
```

### Ejemplo con diferentes tipos de datos

```php
// Filtros combinados
$posts = $orm->table('posts')
    ->where('published', '=', true)
    ->where('user_id', '=', 5)
    ->where('created_at', '>', '2024-01-01')
    ->getAll();

foreach ($posts as $post) {
    echo "Post: {$post['title']} - Usuario: {$post['user_id']}\n";
}
```

**SQL Equivalente:**
```sql
SELECT * FROM posts
WHERE published = 1
  AND user_id = 5
  AND created_at > '2024-01-01';
```

## Condiciones con OR

### Usando `orWhere()`

```php
// Usuarios activos O administradores
$usuarios = $orm->table('users')
    ->where('active', '=', true)
    ->orWhere('role', '=', 'admin')
    ->getAll();

echo "Usuarios activos o administradores: " . count($usuarios) . "\n";
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE active = 1 OR role = 'admin';
```

### Combinando AND y OR

```php
// Usuarios activos Y (mayores de 18 O administradores)
$usuarios = $orm->table('users')
    ->where('active', '=', true)
    ->where(function($query) {
        $query->where('age', '>', 18)
              ->orWhere('role', '=', 'admin');
    })
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM users
WHERE active = 1
  AND (age > 18 OR role = 'admin');
```

## Operador LIKE para búsquedas de texto

### Búsqueda básica con LIKE

```php
// Usuarios cuyo nombre contiene "juan"
$usuarios = $orm->table('users')
    ->where('name', 'LIKE', '%juan%')
    ->getAll();

// Usuarios cuyo email termina en "gmail.com"
$usuariosGmail = $orm->table('users')
    ->where('email', 'LIKE', '%gmail.com')
    ->getAll();

// Usuarios cuyo nombre empieza con "A"
$usuariosA = $orm->table('users')
    ->where('name', 'LIKE', 'A%')
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE name LIKE '%juan%';
SELECT * FROM users WHERE email LIKE '%gmail.com';
SELECT * FROM users WHERE name LIKE 'A%';
```

### Búsqueda insensible a mayúsculas

```php
// Búsqueda case-insensitive (depende de la configuración de BD)
$usuarios = $orm->table('users')
    ->where('name', 'ILIKE', '%JUAN%') // PostgreSQL
    ->getAll();

// Alternativa usando LOWER
$usuarios = $orm->table('users')
    ->whereRaw('LOWER(name) LIKE ?', ['%juan%'])
    ->getAll();
```

## Operador IN para múltiples valores

### Ejemplo básico con IN

```php
// Usuarios con IDs específicos
$ids = [1, 3, 5, 7];
$usuarios = $orm->table('users')
    ->whereIn('id', $ids)
    ->getAll();

// Posts de categorías específicas
$categorias = ['tecnologia', 'ciencia', 'educacion'];
$posts = $orm->table('posts')
    ->whereIn('category', $categorias)
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE id IN (1, 3, 5, 7);
SELECT * FROM posts WHERE category IN ('tecnologia', 'ciencia', 'educacion');
```

### Operador NOT IN

```php
// Usuarios que NO son administradores ni moderadores
$rolesExcluidos = ['admin', 'moderator'];
$usuarios = $orm->table('users')
    ->whereNotIn('role', $rolesExcluidos)
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE role NOT IN ('admin', 'moderator');
```

## Operador BETWEEN para rangos

### Ejemplo con fechas

```php
// Posts creados en enero 2024
$posts = $orm->table('posts')
    ->whereBetween('created_at', ['2024-01-01', '2024-01-31'])
    ->getAll();

// Usuarios entre 18 y 65 años
$usuarios = $orm->table('users')
    ->whereBetween('age', [18, 65])
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM posts WHERE created_at BETWEEN '2024-01-01' AND '2024-01-31';
SELECT * FROM users WHERE age BETWEEN 18 AND 65;
```

### NOT BETWEEN

```php
// Productos fuera del rango de precio normal
$productos = $orm->table('products')
    ->whereNotBetween('price', [10, 100])
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM products WHERE price NOT BETWEEN 10 AND 100;
```

## Valores NULL

### Verificar NULL

```php
// Usuarios sin fecha de último login
$usuariosSinLogin = $orm->table('users')
    ->whereNull('last_login')
    ->getAll();

// Posts sin categoría asignada
$postsSinCategoria = $orm->table('posts')
    ->whereNull('category_id')
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE last_login IS NULL;
SELECT * FROM posts WHERE category_id IS NULL;
```

### Verificar NOT NULL

```php
// Usuarios que han hecho login al menos una vez
$usuariosConLogin = $orm->table('users')
    ->whereNotNull('last_login')
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE last_login IS NOT NULL;
```

## Condiciones complejas con agrupación

### Ejemplo avanzado

```php
// (Usuarios activos Y mayores de 18) O (administradores Y verificados)
$usuarios = $orm->table('users')
    ->where(function($query) {
        $query->where('active', '=', true)
              ->where('age', '>', 18);
    })
    ->orWhere(function($query) {
        $query->where('role', '=', 'admin')
              ->where('verified', '=', true);
    })
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM users
WHERE (active = 1 AND age > 18)
   OR (role = 'admin' AND verified = 1);
```

### Ejemplo con múltiples niveles

```php
// Consulta compleja con múltiples agrupaciones
$posts = $orm->table('posts')
    ->where('published', '=', true)
    ->where(function($query) {
        $query->where(function($subQuery) {
            $subQuery->where('category', '=', 'tecnologia')
                     ->where('views', '>', 1000);
        })
        ->orWhere(function($subQuery) {
            $subQuery->where('featured', '=', true)
                     ->where('created_at', '>', '2024-01-01');
        });
    })
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM posts
WHERE published = 1
  AND ((category = 'tecnologia' AND views > 1000)
       OR (featured = 1 AND created_at > '2024-01-01'));
```

## Consultas dinámicas

### Filtros opcionales

```php
function buscarUsuarios($filtros = []) {
    $query = $orm->table('users');

    // Aplicar filtros solo si están presentes
    if (!empty($filtros['name'])) {
        $query->where('name', 'LIKE', '%' . $filtros['name'] . '%');
    }

    if (!empty($filtros['email'])) {
        $query->where('email', 'LIKE', '%' . $filtros['email'] . '%');
    }

    if (isset($filtros['active'])) {
        $query->where('active', '=', $filtros['active']);
    }

    if (!empty($filtros['min_age'])) {
        $query->where('age', '>=', $filtros['min_age']);
    }

    if (!empty($filtros['max_age'])) {
        $query->where('age', '<=', $filtros['max_age']);
    }

    return $query->getAll();
}

// Uso de la función
$usuarios = buscarUsuarios([
    'name' => 'juan',
    'active' => true,
    'min_age' => 18
]);
```

## Ejemplo práctico completo

```php
<?php
require_once 'config/database.php';

try {
    echo "=== Filtros WHERE Avanzados ===\n\n";

    // 1. Búsqueda con LIKE
    echo "1. Usuarios con 'admin' en el email:\n";
    $admins = $orm->table('users')
        ->where('email', 'LIKE', '%admin%')
        ->getAll();

    foreach ($admins as $admin) {
        echo "- {$admin['name']} ({$admin['email']})\n";
    }

    // 2. Filtros con IN
    echo "\n2. Posts de categorías específicas:\n";
    $posts = $orm->table('posts')
        ->whereIn('category', ['tecnologia', 'ciencia'])
        ->where('published', '=', true)
        ->getAll();

    foreach ($posts as $post) {
        echo "- {$post['title']} (Categoría: {$post['category']})\n";
    }

    // 3. Rangos con BETWEEN
    echo "\n3. Posts del último mes:\n";
    $fechaInicio = date('Y-m-01'); // Primer día del mes actual
    $fechaFin = date('Y-m-t');     // Último día del mes actual

    $postsRecientes = $orm->table('posts')
        ->whereBetween('created_at', [$fechaInicio, $fechaFin])
        ->orderBy('created_at', 'DESC')
        ->getAll();

    foreach ($postsRecientes as $post) {
        echo "- {$post['title']} ({$post['created_at']})\n";
    }

    // 4. Condiciones complejas
    echo "\n4. Usuarios activos O administradores:\n";
    $usuariosEspeciales = $orm->table('users')
        ->where('active', '=', true)
        ->orWhere('role', '=', 'admin')
        ->orderBy('name')
        ->getAll();

    foreach ($usuariosEspeciales as $usuario) {
        $tipo = $usuario['role'] === 'admin' ? 'Admin' : 'Usuario';
        $estado = $usuario['active'] ? 'Activo' : 'Inactivo';
        echo "- {$usuario['name']} ($tipo, $estado)\n";
    }

} catch (VersaORMException $e) {
    echo "Error en la consulta: " . $e->getMessage() . "\n";
}
```

## Mejores prácticas

### ✅ Recomendado

```php
// Usar parámetros en lugar de concatenar strings
$orm->table('users')->where('name', 'LIKE', '%' . $busqueda . '%');

// Agrupar condiciones lógicamente
$query->where(function($q) {
    $q->where('condition1', '=', true)
      ->where('condition2', '>', 10);
});

// Verificar arrays antes de usar whereIn
if (!empty($ids)) {
    $query->whereIn('id', $ids);
}
```

### ❌ Evitar

```php
// No concatenar directamente en la consulta (riesgo de SQL injection)
$orm->table('users')->whereRaw("name LIKE '%$busqueda%'");

// No usar condiciones complejas sin agrupar
$query->where('a', '=', 1)
      ->orWhere('b', '=', 2)
      ->where('c', '=', 3); // Lógica confusa

// No usar whereIn con arrays vacíos
$query->whereIn('id', []); // Puede causar errores
```

## Errores comunes

### Error: Array vacío en whereIn
```php
$ids = []; // Array vacío
$orm->table('users')->whereIn('id', $ids)->getAll(); // Puede fallar

// Solución:
if (!empty($ids)) {
    $orm->table('users')->whereIn('id', $ids)->getAll();
}
```

### Error: Paréntesis mal balanceados
```php
// Incorrecto: lógica confusa
$query->where('a', '=', 1)
      ->orWhere('b', '=', 2)
      ->where('c', '=', 3);

// Correcto: usar agrupación
$query->where('a', '=', 1)
      ->where(function($q) {
          $q->where('b', '=', 2)
            ->orWhere('c', '=', 3);
      });
```

## Siguiente paso

Ahora que dominas los filtros WHERE, aprende sobre [JOINs](joins.md) para combinar datos de múltiples tablas.

## Navegación

- **Anterior**: [Consultas Simples](consultas-simples.md)
- **Siguiente**: [JOINs](joins.md)
- **Índice**: [Documentación Principal](../README.md)
