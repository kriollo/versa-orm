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
$usuario = VersaModel::dispense('users');
$usuario->name = 'Juan Pérez';
$usuario->email = 'juan@ejemplo.com';
$usuario->active = true;

$usuario->store();
echo "Usuario creado con ID: " . $usuario->id;
```

**SQL Equivalente:**
```sql
INSERT INTO users (name, email, active) VALUES ('Juan Pérez', 'juan@ejemplo.com', 1);
```

**Devuelve:** El modelo almacenado con ID asignado

### Crear múltiples registros

```php
// Crear varios usuarios de una vez
$usuarios = [];

$usuario1 = VersaModel::dispense('users');
$usuario1->name = 'María García';
$usuario1->email = 'maria@ejemplo.com';
$usuarios[] = $usuario1;

$usuario2 = VersaModel::dispense('users');
$usuario2->name = 'Carlos López';
$usuario2->email = 'carlos@ejemplo.com';
$usuarios[] = $usuario2;

VersaModel::storeAll($usuarios);
echo "Usuarios creados con IDs: " . $usuario1->id . ', ' . $usuario2->id;
```

**SQL Equivalente:**
```sql
INSERT INTO users (name, email) VALUES
('María García', 'maria@ejemplo.com'),
('Carlos López', 'carlos@ejemplo.com');
```

**Devuelve:** Array de modelos almacenados con IDs asignados

## READ - Leer registros

### Leer un registro por ID

```php
// Cargar usuario por ID
$usuario = VersaModel::load('users', 1);

if ($usuario !== null) {
    echo "Usuario encontrado: " . $usuario->name;
    echo "Email: " . $usuario->email;
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
$usuarios = VersaModel::findAll('users', 'active = ?', [true]);

foreach ($usuarios as $usuario) {
    echo "ID: " . $usuario->id . " - Nombre: " . $usuario->name . "\n";
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
$usuarios = VersaModel::findAll('users', 'name LIKE ? AND active = ?', ['%Juan%', true]);

echo "Usuarios encontrados: " . count($usuarios);
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
$usuario = VersaModel::load('users', 1);

if ($usuario !== null) {
    $usuario->name = 'Juan Carlos Pérez';
    $usuario->email = 'juancarlos@ejemplo.com';

    $usuario->store();
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
$usuariosInactivos = VersaModel::findAll('users', 'active = ?', [false]);

foreach ($usuariosInactivos as $usuario) {
    $usuario->active = true;
    $usuario->store();
}

echo "Activados " . count($usuariosInactivos) . " usuarios";
```

**SQL Equivalente:**
```sql
UPDATE users SET active = 1 WHERE active = 0;
```

### Actualizar con validación

```php
// Actualizar email con validación
$usuario = VersaModel::load('users', 1);

if ($usuario !== null) {
    $nuevoEmail = 'nuevo@ejemplo.com';

    // Verificar que el email no exista
    $existeEmail = VersaModel::findOne('users', 'email = ? AND id != ?', [$nuevoEmail, $usuario->id]);

    if ($existeEmail === null) {
        $usuario->email = $nuevoEmail;
        $usuario->store();
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
$usuario = VersaModel::load('users', 1);

if ($usuario !== null) {
    $usuario->trash();
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
$usuariosInactivos = VersaModel::findAll('users', 'active = ?', [false]);

foreach ($usuariosInactivos as $usuario) {
    $usuario->trash();
}

echo "Eliminados " . count($usuariosInactivos) . " usuarios inactivos";
```

**SQL Equivalente:**
```sql
DELETE FROM users WHERE active = 0;
```

### Eliminación suave (Soft Delete)

```php
// En lugar de eliminar, marcar como inactivo
$usuario = VersaModel::load('users', 1);

if ($usuario !== null) {
    $usuario->active = false;
    $usuario->deleted_at = date('Y-m-d H:i:s');
    $usuario->store();
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
    $usuario = VersaModel::dispense('users');
    $usuario->name = 'Ana Martínez';
    $usuario->email = 'ana@ejemplo.com';
    $usuario->active = true;

    $usuario->store();
    echo "Usuario creado con ID: " . $usuario->id . "\n\n";

    // READ - Leer usuario
    echo "=== LEER USUARIO ===\n";
    $usuarioLeido = VersaModel::load('users', $usuario->id);
    echo "Nombre: " . $usuarioLeido->name . "\n";
    echo "Email: " . $usuarioLeido->email . "\n\n";

    // UPDATE - Actualizar usuario
    echo "=== ACTUALIZAR USUARIO ===\n";
    $usuarioLeido->name = 'Ana Isabel Martínez';
    $usuarioLeido->store();
    echo "Usuario actualizado\n\n";

    // READ - Verificar actualización
    echo "=== VERIFICAR ACTUALIZACIÓN ===\n";
    $usuarioActualizado = VersaModel::load('users', $usuario->id);
    echo "Nuevo nombre: " . $usuarioActualizado->name . "\n\n";

    // DELETE - Eliminar usuario
    echo "=== ELIMINAR USUARIO ===\n";
    $usuarioActualizado->trash();
    echo "Usuario eliminado\n\n";

    // READ - Verificar eliminación
    echo "=== VERIFICAR ELIMINACIÓN ===\n";
    $usuarioEliminado = VersaModel::load('users', $usuario->id);
    if ($usuarioEliminado === null) {
        echo "Usuario eliminado correctamente\n";
    }

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

## Mejores prácticas

### 1. Siempre verificar existencia antes de actualizar/eliminar
```php
$usuario = VersaModel::load('users', $id);
if ($usuario !== null) {
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
    $usuario1->store();
    $usuario2->store();
    $orm->exec('COMMIT');
} catch (Exception $e) {
    $orm->exec('ROLLBACK');
    throw $e;
}
```

### 3. Validar datos antes de guardar
```php
if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $usuario->email = $email;
    $usuario->store();
} else {
    throw new InvalidArgumentException('Email inválido');
}
```

## Errores comunes

### 1. No verificar si el registro existe
```php
// ❌ Incorrecto
$usuario = VersaModel::load('users', 999);
$usuario->name = 'Nuevo nombre'; // Error si no existe

// ✅ Correcto
$usuario = VersaModel::load('users', 999);
if ($usuario !== null) {
    $usuario->name = 'Nuevo nombre';
    $usuario->store();
}
```

### 2. No manejar excepciones
```php
// ❌ Incorrecto
$usuario->store(); // Puede fallar sin aviso

// ✅ Correcto
try {
    $usuario->store();
} catch (VersaORMException $e) {
    echo "Error al guardar: " . $e->getMessage();
}
```

## Próximos pasos

Ahora que conoces las operaciones CRUD básicas, puedes continuar con:
- [VersaModel](versamodel.md) - Profundizar en los métodos de VersaModel
- [Manejo de Errores](manejo-errores.md) - Aprender a manejar excepciones
- [Query Builder](../04-query-builder/README.md) - Para consultas más complejas
