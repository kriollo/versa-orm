# CRUD Básico con VersaORM

Las operaciones CRUD (Create, Read, Update, Delete) son la base de cualquier aplicación que trabaje con bases de datos. VersaORM hace estas operaciones simples y seguras.

## Configuración inicial

Antes de empezar, asegúrate de tener VersaORM configurado:

```php
<?php
require_once 'vendor/autoload.php';

use VersaORM\VersaORM;

// Configuración de la base de datos
$orm = new VersaORM([
    'host' => 'localhost',
    'database' => 'mi_app',
    'username' => 'usuario',
    'password' => 'contraseña',
    'driver' => 'mysql'
]);
```

## CREATE - Crear registros

### Crear un registro simple

```php
// Crear un nuevo usuario
$user = VersaModel::dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan@ejemplo.com';
$user->active = true;

$user->store();
echo "Usuario creado con ID: " . $user->id;
```

**SQL Equivalente:**
```sql
INSERT INTO users (name, email, active) VALUES ('Juan Pérez', 'juan@ejemplo.com', 1);
```

**Devuelve:** El modelo almacenado con ID asignado

### Crear múltiples registros

```php
// Crear varios usuarios de una vez
$users = [];

$user1 = VersaModel::dispense('users');
$user1->name = 'María García';
$user1->email = 'maria@ejemplo.com';
$users[] = $user1;

$user2 = VersaModel::dispense('users');
$user2->name = 'Carlos López';
$user2->email = 'carlos@ejemplo.com';
$users[] = $user2;

// Devuelve array de IDs en el mismo orden
$ids = VersaModel::storeAll($users);
echo "Usuarios creados con IDs: " . implode(', ', $ids);
```

**SQL Equivalente:**
```sql
INSERT INTO users (name, email) VALUES
('María García', 'maria@ejemplo.com'),
('Carlos López', 'carlos@ejemplo.com');
```

**Devuelve:** Array de IDs (int|string|null) en el mismo orden de entrada

## READ - Leer registros

### Leer un registro por ID

```php
// Cargar usuario por ID
$user = VersaModel::load('users', 1);

if ($user !== null) {
    echo "Usuario encontrado: " . $user->name;
    echo "Email: " . $user->email;
} else {
    echo "Usuario no encontrado";
}
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE id = 1;
```

**Devuelve:** Objeto VersaModel o null si no existe

### Leer múltiples registros

```php
// Obtener todos los usuarios activos
$users = VersaModel::findAll('users', 'active = ?', [true]);

foreach ($users as $user) {
    echo "ID: " . $user->id . " - Nombre: " . $user->name . "\n";
}
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE active = 1;
```

**Devuelve:** Array de objetos VersaModel

### Leer con condiciones múltiples

```php
// Buscar usuarios por nombre y estado
$users = VersaModel::findAll('users', 'name LIKE ? AND active = ?', ['%Juan%', true]);

echo "Usuarios encontrados: " . count($users);
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE name LIKE '%Juan%' AND active = 1;
```

**Devuelve:** Array de objetos VersaModel

## UPDATE - Actualizar registros

### Actualizar un registro existente

```php
// Cargar y actualizar usuario
$user = VersaModel::load('users', 1);

if ($user !== null) {
    $user->name = 'Juan Carlos Pérez';
    $user->email = 'juancarlos@ejemplo.com';

    $user->store();
    echo "Usuario actualizado correctamente";
} else {
    echo "Usuario no encontrado";
}
```

**SQL Equivalente:**
```sql
UPDATE users SET name = 'Juan Carlos Pérez', email = 'juancarlos@ejemplo.com' WHERE id = 1;
```

**Devuelve:** El modelo actualizado

### Actualizar múltiples registros

```php
// Activar todos los usuarios inactivos
$inactiveUsers = VersaModel::findAll('users', 'active = ?', [false]);

foreach ($inactiveUsers as $user) {
    $user->active = true;
    $user->store();
}

echo "Activados " . count($inactiveUsers) . " usuarios";
```

**SQL Equivalente:**
```sql
UPDATE users SET active = 1 WHERE active = 0;
```

### Actualizar con validación

```php
// Actualizar email con validación
$user = VersaModel::load('users', 1);

if ($user !== null) {
    $newEmail = 'nuevo@ejemplo.com';

    // Verificar que el email no exista
    $emailExists = VersaModel::findOne('users', 'email = ? AND id != ?', [$newEmail, $user->id]);

    if ($emailExists === null) {
        $user->email = $newEmail;
        $user->store();
        echo "Email actualizado correctamente";
    } else {
        echo "El email ya está en uso";
    }
}
```

## DELETE - Eliminar registros

### Eliminar un registro

```php
// Eliminar usuario por ID
$user = VersaModel::load('users', 1);

if ($user !== null) {
    $user->trash();
    echo "Usuario eliminado correctamente";
} else {
    echo "Usuario no encontrado";
}
```

**SQL Equivalente:**
```sql
DELETE FROM users WHERE id = 1;
```

**Devuelve:** void (no devuelve valor)

### Eliminar con condiciones

```php
// Eliminar usuarios inactivos
$inactiveUsers = VersaModel::findAll('users', 'active = ?', [false]);

foreach ($inactiveUsers as $user) {
    $user->trash();
}

echo "Eliminados " . count($inactiveUsers) . " usuarios inactivos";
```

**SQL Equivalente:**
```sql
DELETE FROM users WHERE active = 0;
```

### Eliminación suave (Soft Delete)

```php
// En lugar de eliminar, marcar como inactivo
$user = VersaModel::load('users', 1);

if ($user !== null) {
    $user->active = false;
    $user->deleted_at = date('Y-m-d H:i:s');
    $user->store();
    echo "Usuario desactivado (eliminación suave)";
}
```

## Ejemplo completo: Gestión de usuarios

```php
<?php
require_once 'vendor/autoload.php';

use VersaORM\VersaORM;
use VersaORM\VersaORMException;

try {
    $orm = new VersaORM([
        'host' => 'localhost',
        'database' => 'mi_app',
        'username' => 'usuario',
        'password' => 'contraseña',
        'driver' => 'mysql'
    ]);

    // Configurar VersaModel para usar esta instancia de ORM
    VersaModel::setORM($orm);

    // CREATE - Crear nuevo usuario
    echo "=== CREAR USUARIO ===\n";
    $user = VersaModel::dispense('users');
    $user->name = 'Ana Martínez';
    $user->email = 'ana@ejemplo.com';
    $user->active = true;

    $user->store();
    echo "Usuario creado con ID: " . $user->id . "\n\n";

    // READ - Leer usuario
    echo "=== LEER USUARIO ===\n";
    $readUser = VersaModel::load('users', $user->id);
    echo "Nombre: " . $readUser->name . "\n";
    echo "Email: " . $readUser->email . "\n\n";

    // UPDATE - Actualizar usuario
    echo "=== ACTUALIZAR USUARIO ===\n";
    $readUser->name = 'Ana Isabel Martínez';
    $readUser->store();
    echo "Usuario actualizado\n\n";

    // READ - Verificar actualización
    echo "=== VERIFICAR ACTUALIZACIÓN ===\n";
    $updatedUser = VersaModel::load('users', $user->id);
    echo "Nuevo nombre: " . $updatedUser->name . "\n\n";

    // DELETE - Eliminar usuario
    echo "=== ELIMINAR USUARIO ===\n";
    $updatedUser->trash();
    echo "Usuario eliminado\n\n";

    // READ - Verificar eliminación
    echo "=== VERIFICAR ELIMINACIÓN ===\n";
    $deletedUser = VersaModel::load('users', $user->id);
    if ($deletedUser === null) {
        echo "Usuario eliminado correctamente\n";
    }

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

## Mejores prácticas

### 1. Siempre verificar existencia antes de actualizar/eliminar
```php
$user = VersaModel::load('users', $id);
if ($user !== null) {
    // Proceder con la operación
} else {
    // Manejar caso de registro no encontrado
}
```

### 2. Usar transacciones para operaciones múltiples
```php
$orm->exec('BEGIN');
try {
    // Múltiples operaciones
    $user1->store();
    $user2->store();
    $orm->exec('COMMIT');
} catch (Exception $e) {
    $orm->exec('ROLLBACK');
    throw $e;
}
```

### 3. Validar datos antes de guardar
```php
if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $user->email = $email;
    $user->store();
} else {
    throw new InvalidArgumentException('Email inválido');
}
```

## Errores comunes

### 1. No verificar si el registro existe
```php
// ❌ Incorrecto
$user = VersaModel::load('users', 999);
$user->name = 'Nuevo nombre'; // Error si no existe

// ✅ Correcto
$user = VersaModel::load('users', 999);
if ($user !== null) {
    $user->name = 'Nuevo nombre';
    $user->store();
}
```

### 2. No manejar excepciones
```php
// ❌ Incorrecto
$user->store(); // Puede fallar sin aviso

// ✅ Correcto
try {
    $user->store();
} catch (VersaORMException $e) {
    echo "Error al guardar: " . $e->getMessage();
}
```

## Próximos pasos

Ahora que conoces las operaciones CRUD básicas, puedes continuar con:
- [VersaModel](versamodel.md) - Profundizar en los métodos de VersaModel
- [Manejo de Errores](manejo-errores.md) - Aprender a manejar excepciones
- [Query Builder](../04-query-builder/README.md) - Para consultas más complejas
