# Consultas Simples con Query Builder

El Query Builder te permite construir consultas SQL de manera intuitiva usando métodos encadenados. Empezaremos con los conceptos básicos.


## Conceptos Clave

- **Método `table()`**: Especifica la tabla principal.
- **Método `where()`**: Agrega condiciones de filtrado.
- **Métodos de ejecución**: `getAll()` (array de arrays), `findAll()` (array de modelos), `firstArray()` (array asociativo), `findOne()` (modelo), `count()` (entero).
- **Encadenamiento**: Los métodos se pueden encadenar para construir consultas complejas.

> **Nota para principiantes:** Siempre verifica el tipo de retorno de cada método. Si esperas un solo resultado, usa `firstArray()` o `findOne()`. Si esperas varios, usa `getAll()` o `findAll()`.

## Seleccionar todos los registros


### Ejemplo VersaORM
```php
$usuarios = $orm->table('users')->getAll();
foreach ($usuarios as $usuario) {
    echo "ID: {$usuario['id']}, Nombre: {$usuario['name']}\n";
}
```

### Ejemplo SQL equivalente
```sql
SELECT * FROM users;
```

**Devuelve:** Array de arrays asociativos con todos los registros.

## Seleccionar con condición WHERE simple


### Ejemplo VersaORM
```php
$usuariosActivos = $orm->table('users')
    ->where('active', '=', true)
    ->getAll();
echo "Usuarios activos encontrados: " . count($usuariosActivos) . "\n";
```

### Ejemplo SQL equivalente
```sql
SELECT * FROM users WHERE active = 1;
```

**Devuelve:** Array de arrays asociativos que cumplen la condición.

### Ejemplo con diferentes tipos de datos

```php
// Buscar por ID (número) - devuelve array
$usuario = $orm->table('users')
    ->where('id', '=', 1)
    ->firstArray();

if ($usuario) {
    echo "Usuario encontrado: {$usuario['name']}\n";
} else {
    echo "Usuario no encontrado\n";
}

// Buscar por email (string) - devuelve modelo
$usuarioPorEmail = $orm->table('users')
    ->where('email', '=', 'juan@example.com')
    ->findOne();

// Buscar por fecha
$usuariosRecientes = $orm->table('users')
    ->where('created_at', '>', '2024-01-01')
    ->getAll();
```

**SQL Equivalente:**
```sql
-- Por ID
SELECT * FROM users WHERE id = 1 LIMIT 1;

-- Por email
SELECT * FROM users WHERE email = 'juan@example.com' LIMIT 1;

-- Por fecha
SELECT * FROM users WHERE created_at > '2024-01-01';
```

## Operadores básicos de comparación

### Operadores disponibles

```php
// Igual
$orm->table('users')->where('age', '=', 25)->getAll();

// Mayor que
$orm->table('users')->where('age', '>', 18)->getAll();

// Mayor o igual que
$orm->table('users')->where('age', '>=', 21)->getAll();

// Menor que
$orm->table('users')->where('age', '<', 65)->getAll();

// Menor o igual que
$orm->table('users')->where('age', '<=', 30)->getAll();

// Diferente
$orm->table('users')->where('status', '!=', 'banned')->getAll();
$orm->table('users')->where('status', '<>', 'banned')->getAll(); // Alternativa
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE age = 25;
SELECT * FROM users WHERE age > 18;
SELECT * FROM users WHERE age >= 21;
SELECT * FROM users WHERE age < 65;
SELECT * FROM users WHERE age <= 30;
SELECT * FROM users WHERE status != 'banned';
SELECT * FROM users WHERE status <> 'banned';
```

## Métodos de ejecución


### `getAll()` - Obtener todos los resultados (array de arrays)
```php
$todos = $orm->table('users')
    ->where('active', '=', true)
    ->getAll();
echo "Tipo de retorno: " . gettype($todos) . "\n";
echo "Cantidad de registros: " . count($todos) . "\n";
```
**Devuelve:** Array de arrays asociativos (puede estar vacío).


### `firstArray()` - Obtener un solo resultado como array asociativo
```php
$primero = $orm->table('users')
    ->where('active', '=', true)
    ->firstArray();
if ($primero) {
    echo "Tipo de retorno: " . gettype($primero) . "\n";
    echo "Nombre: {$primero['name']}\n";
} else {
    echo "No se encontraron resultados\n";
}
```
**Devuelve:** Array asociativo o `null` si no hay resultados.


### `findAll()` - Obtener todos los resultados como modelos VersaModel
```php
$usuarios = $orm->table('users')
    ->where('active', '=', true)
    ->findAll();
foreach ($usuarios as $usuario) {
    echo "Usuario: {$usuario->name} (ID: {$usuario->id})\n";
}
```
**Devuelve:** Array de objetos VersaModel.


### `findOne()` - Obtener un solo resultado como modelo VersaModel
```php
$usuario = $orm->table('users')
    ->where('email', '=', 'juan@example.com')
    ->findOne();
if ($usuario) {
    echo "Usuario encontrado: {$usuario->name}\n";
} else {
    echo "Usuario no encontrado\n";
}
```
**Devuelve:** Objeto VersaModel o `null` si no hay resultados.


### `count()` - Contar registros
```php
$cantidad = $orm->table('users')
    ->where('active', '=', true)
    ->count();
echo "Usuarios activos: $cantidad\n";
echo "Tipo de retorno: " . gettype($cantidad) . "\n";
```

### SQL equivalente
```sql
SELECT COUNT(*) FROM users WHERE active = 1;
```
**Devuelve:** Entero con el número de registros.

## Ejemplo práctico completo

```php
<?php
require_once 'config/database.php';

try {
    // Contar todos los usuarios
    $totalUsuarios = $orm->table('users')->count();
    echo "Total de usuarios: $totalUsuarios\n\n";

    // Obtener usuarios activos
    $usuariosActivos = $orm->table('users')
        ->where('active', '=', true)
        ->getAll();

    echo "Usuarios activos (" . count($usuariosActivos) . "):\n";
    foreach ($usuariosActivos as $usuario) {
        echo "- {$usuario['name']} ({$usuario['email']})\n";
    }

    // Buscar un usuario específico
    $usuarioEspecifico = $orm->table('users')
        ->where('email', '=', 'admin@example.com')
        ->firstArray();

    if ($usuarioEspecifico) {
        echo "\nAdministrador encontrado: {$usuarioEspecifico['name']}\n";
    } else {
        echo "\nAdministrador no encontrado\n";
    }

} catch (VersaORMException $e) {
    echo "Error en la consulta: " . $e->getMessage() . "\n";
}
```

## Mejores prácticas

### ✅ Recomendado

```php
// Usar firstArray() cuando esperas un solo resultado como array
$usuario = $orm->table('users')->where('id', '=', 1)->firstArray();

// Usar findOne() cuando esperas un solo resultado como modelo
$usuarioModelo = $orm->table('users')->where('id', '=', 1)->findOne();

// Verificar resultados antes de usar
if ($usuario) {
    echo $usuario['name'];
}

// Usar count() para verificar existencia
$existe = $orm->table('users')->where('email', '=', $email)->count() > 0;
```

### ❌ Evitar

```php
// No usar getAll() para un solo resultado
$usuarios = $orm->table('users')->where('id', '=', 1)->getAll();
$usuario = $usuarios[0]; // Puede causar error si está vacío

// No asumir que siempre hay resultados
$usuario = $orm->table('users')->where('id', '=', 999)->firstArray();
echo $usuario['name']; // Error si $usuario es null
```

## Errores comunes

### Error: Tabla no existe
```php
// Error: tabla mal escrita
$orm->table('user')->getAll(); // Debería ser 'users'
```

### Error: Columna no existe
```php
// Error: columna mal escrita
$orm->table('users')->where('activo', '=', true)->getAll(); // Debería ser 'active'
```

### Error: Acceso a índice inexistente
```php
$usuario = $orm->table('users')->where('id', '=', 999)->firstArray();
// $usuario puede ser null
echo $usuario['name']; // Error si $usuario es null

// Solución:
if ($usuario) {
    echo $usuario['name'];
}
```

## Siguiente paso


---

> **Tip para principiantes:** Siempre revisa el tipo de retorno y valida los resultados antes de acceder a los datos. Si tienes dudas, consulta la [Referencia SQL](../../08-referencia-sql/README.md) para ver equivalencias y ejemplos.

Ahora que dominas las consultas básicas, aprende sobre [Filtros WHERE avanzados](filtros-where.md) para crear condiciones más complejas.

## Navegación

- **Anterior**: [Query Builder - Introducción](README.md)
- **Siguiente**: [Filtros WHERE](filtros-where.md)
- **Índice**: [Documentación Principal](../README.md)
