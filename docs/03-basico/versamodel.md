# VersaModel: Trabajando con Modelos

VersaModel es el corazón de VersaORM. Representa un registro de base de datos como un objeto PHP, permitiendo tratos de forma intuitiva y orientada a objetos.

## Los cuatro métodos fundamentales

VersaORM se basa en cuatro métodos principales que cubren todo el ciclo de vida de un registro:

1. **`dispense()`** - Crear un nuevo modelo vacío
2. **`load()`** - Cargar un modelo existente desde la base de datos
3. **`store()`** - Guardar un modelo (crear o actualizar)
4. **`trash()`** - Eliminar un modelo

## dispense() - Crear modelos vacíos

El método `dispense()` crea un nuevo objeto VersaModel vacío, listo para ser llenado con datos.

### Sintaxis básica

```php
$modelo = VersaModel::dispense('nombre_tabla');
```

**Devuelve:** Objeto VersaModel vacío

### Ejemplos prácticos

```php
// Crear un nuevo usuario
$usuario = VersaModel::dispense('users');
echo get_class($usuario); // VersaORM\VersaModel
echo $usuario->id; // null (aún no tiene ID)

// Asignar propiedades
$usuario->name = 'Pedro Sánchez';
$usuario->email = 'pedro@ejemplo.com';
$usuario->active = true;

// En este punto el usuario existe solo en memoria
// No se ha guardado en la base de datos aún
```

### Crear múltiples modelos

```php
// Crear varios modelos de una vez
$usuarios = [];
for ($i = 0; $i < 3; $i++) {
    $usuarios[] = VersaModel::dispense('users');
}

$usuarios[0]->name = 'Usuario 1';
$usuarios[1]->name = 'Usuario 2';
$usuarios[2]->name = 'Usuario 3';

// Todos están en memoria, no en la base de datos
```

**SQL Equivalente:** No hay equivalente directo, ya que `dispense()` no ejecuta SQL.

## load() - Cargar modelos existentes

El método `load()` recupera un registro existente de la base de datos y lo convierte en un objeto VersaModel.

### Sintaxis básica

```php
$modelo = VersaModel::load('nombre_tabla', $id);
```

**Devuelve:** Objeto VersaModel o null si no existe el registro

### Ejemplos prácticos

```php
// Cargar usuario por ID
$usuario = VersaModel::load('users', 1);

if ($usuario !== null) {
    echo "Usuario encontrado: " . $usuario->name;
    echo "Email: " . $usuario->email;
    echo "Activo: " . ($usuario->active ? 'Sí' : 'No');
} else {
    echo "Usuario con ID 1 no existe";
}
```

**SQL Equivalente:**
```sql
SELECT * FROM users WHERE id = 1;
```

### Verificar si un modelo existe

```php
// Método recomendado para verificar existencia
$usuario = VersaModel::load('users', 999);

if ($usuario !== null) {
    echo "El usuario existe";
} else {
    echo "El usuario no existe";
}

// También puedes verificar directamente
if ($usuario === null) {
    echo "El modelo no existe en BD";
}
```

### Cargar con valores por defecto

```php
// Si el usuario no existe, crear uno nuevo con valores por defecto
$usuario = VersaModel::load('users', 999);

if ($usuario === null) {
    $usuario = VersaModel::dispense('users');
    $usuario->name = 'Usuario por defecto';
    $usuario->email = 'default@ejemplo.com';
    $usuario->active = false;
}
```

## store() - Guardar modelos

El método `store()` guarda un modelo en la base de datos. Automáticamente determina si debe hacer INSERT (crear) o UPDATE (actualizar).

### Sintaxis básica

```php
$modelo->store();
```

**Devuelve:** El modelo con ID asignado (si es nuevo)

### Crear nuevo registro (INSERT)

```php
// Crear nuevo usuario
$usuario = VersaModel::dispense('users');
$usuario->name = 'Laura González';
$usuario->email = 'laura@ejemplo.com';
$usuario->active = true;

$usuario->store();
echo "Usuario creado con ID: " . $usuario->id;

// Después del store(), el modelo tiene ID asignado automáticamente
echo "ID del modelo: " . $usuario->id;
```

**SQL Equivalente:**
```sql
INSERT INTO users (name, email, active) VALUES ('Laura González', 'laura@ejemplo.com', 1);
```

### Actualizar registro existente (UPDATE)

```php
// Cargar usuario existente
$usuario = VersaModel::load('users', 1);

if ($usuario !== null) {
    // Modificar propiedades
    $usuario->name = 'Laura María González';
    $usuario->email = 'lauramaria@ejemplo.com';

    $usuario->store();
    echo "Usuario actualizado. ID: " . $usuario->id;
}
```

**SQL Equivalente:**
```sql
UPDATE users SET name = 'Laura María González', email = 'lauramaria@ejemplo.com' WHERE id = 1;
```

### Guardar múltiples modelos

```php
// Crear varios usuarios
$usuarios = [];

$usuario1 = VersaModel::dispense('users');
$usuario1->name = 'Usuario A';
$usuario1->email = 'a@ejemplo.com';
$usuarios[] = $usuario1;

$usuario2 = VersaModel::dispense('users');
$usuario2->name = 'Usuario B';
$usuario2->email = 'b@ejemplo.com';
$usuarios[] = $usuario2;

// Guardar todos de una vez
VersaModel::storeAll($usuarios);
echo "IDs creados: " . $usuario1->id . ', ' . $usuario2->id;
```

**Devuelve:** Array de modelos guardados con IDs asignados

## trash() - Eliminar modelos

El método `trash()` elimina un modelo de la base de datos.

### Sintaxis básica

```php
$modelo->trash();
```

**Devuelve:** void (no devuelve valor)

### Ejemplos prácticos

```php
// Cargar y eliminar usuario
$usuario = VersaModel::load('users', 1);

if ($usuario !== null) {
    $usuario->trash();
    echo "Usuario eliminado";

    // Después del trash(), el modelo se marca como eliminado
    // El ID puede seguir existiendo en memoria
} else {
    echo "Usuario no encontrado";
}
```

**SQL Equivalente:**
```sql
DELETE FROM users WHERE id = 1;
```

### Eliminar múltiples modelos

```php
// Eliminar usuarios inactivos
$usuariosInactivos = VersaModel::findAll('users', 'active = ?', [false]);

foreach ($usuariosInactivos as $usuario) {
    $usuario->trash();
}

echo "Eliminados " . count($usuariosInactivos) . " usuarios";

// O usar trashAll para eliminar múltiples
VersaModel::trashAll($usuariosInactivos);
```

## Propiedades y métodos útiles de VersaModel

### Verificar estado del modelo

```php
$usuario = VersaModel::load('users', 1);

// Verificar si el modelo existe en la base de datos
if ($usuario !== null) {
    echo "El modelo tiene ID, existe en BD";
}

// Verificar si el modelo está vacío
if ($usuario->isEmpty()) {
    echo "El modelo está vacío";
}

// Obtener el nombre de la tabla
echo $usuario->getMeta('type'); // 'users'
```

### Acceder a propiedades

```php
$usuario = VersaModel::load('users', 1);

// Acceso directo a propiedades
echo $usuario->name;
echo $usuario->email;

// Verificar si una propiedad existe
if (isset($usuario->phone)) {
    echo "Teléfono: " . $usuario->phone;
}

// Obtener todas las propiedades como array
$datos = $usuario->export();
print_r($datos);
```

### Modificar propiedades

```php
$usuario = VersaModel::load('users', 1);

// Asignación directa
$usuario->name = 'Nuevo nombre';
$usuario->email = 'nuevo@email.com';

// Asignación condicional
if (!$usuario->phone) {
    $usuario->phone = '123-456-7890';
}

// Guardar cambios
$$usuario->store();
```

## Ejemplo completo: Ciclo de vida de un modelo

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

    echo "=== DISPENSE: Crear modelo vacío ===\n";
    $producto = VersaModel::dispense('products');
    echo "Modelo creado. ID: " . ($producto->id ?? 'null') . "\n";
    echo "¿Está vacío? " . ($producto->isEmpty() ? 'Sí' : 'No') . "\n\n";

    echo "=== Asignar propiedades ===\n";
    $producto->name = 'Laptop Dell';
    $producto->price = 899.99;
    $producto->category = 'Electronics';
    $producto->in_stock = true;
    echo "Propiedades asignadas\n\n";

    echo "=== STORE: Guardar modelo (INSERT) ===\n";
    $id = $$producto->store();
    echo "Producto guardado con ID: $id\n";
    echo "ID del modelo: " . $producto->id . "\n\n";

    echo "=== LOAD: Cargar modelo existente ===\n";
    $productoLeido = VersaModel::load('products', $id);
    echo "Producto cargado: " . $productoLeido->name . "\n";
    echo "Precio: $" . $productoLeido->price . "\n\n";

    echo "=== Modificar y STORE: Actualizar (UPDATE) ===\n";
    $productoLeido->price = 799.99;
    $productoLeido->on_sale = true;
    $idActualizado = $$productoLeido->store();
    echo "Producto actualizado. ID: $idActualizado\n\n";

    echo "=== Verificar actualización ===\n";
    $productoActualizado = VersaModel::load('products', $id);
    echo "Nuevo precio: $" . $productoActualizado->price . "\n";
    echo "En oferta: " . ($productoActualizado->on_sale ? 'Sí' : 'No') . "\n\n";

    echo "=== TRASH: Eliminar modelo ===\n";
    $$productoActualizado->trash();
    echo "Producto eliminado\n";
    echo "ID después de eliminar: " . ($productoActualizado->id ?? 'null') . "\n\n";

    echo "=== Verificar eliminación ===\n";
    $productoEliminado = VersaModel::load('products', $id);
    if ($productoEliminado->isEmpty()) {
        echo "Producto eliminado correctamente\n";
    }

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

## Mejores prácticas con VersaModel

### 1. Siempre verificar existencia antes de operar

```php
// ✅ Correcto
$usuario = VersaModel::load('users', $id);
if ($model !== null) {
    $usuario->name = 'Nuevo nombre';
    $$usuario->store();
}

// ❌ Incorrecto
$usuario = VersaModel::load('users', $id);
$usuario->name = 'Nuevo nombre'; // Error si no existe
$$usuario->store();
```

### 2. Usar nombres de tabla consistentes

```php
// ✅ Correcto - usar nombres en plural
$usuario = VersaModel::dispense('users');
$producto = VersaModel::dispense('products');

// ❌ Evitar - inconsistencia
$usuario = VersaModel::dispense('user');
$producto = VersaModel::dispense('products');
```

### 3. Validar datos antes de guardar

```php
$usuario = VersaModel::dispense('users');
$usuario->name = trim($nombre);

// Validar email
if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $usuario->email = $email;
} else {
    throw new InvalidArgumentException('Email inválido');
}

$$usuario->store();
```

### 4. Manejar modelos vacíos apropiadamente

```php
$usuario = VersaModel::load('users', $id);

if ($usuario->isEmpty()) {
    // Crear nuevo usuario si no existe
    $usuario = VersaModel::dispense('users');
    $usuario->name = 'Usuario por defecto';
}

$$usuario->store();
```

## Comparación con SQL tradicional

| Operación VersaORM | SQL Equivalente | Devuelve |
|-------------------|-----------------|----------|
| `VersaModel::dispense('users')` | N/A (solo en memoria) | VersaModel vacío |
| `VersaModel::load('users', 1)` | `SELECT * FROM users WHERE id = 1` | VersaModel |
| `$$user->store()` (nuevo) | `INSERT INTO users (...)` | ID (integer) |
| `$$user->store()` (existente) | `UPDATE users SET ... WHERE id = ?` | ID (integer) |
| `$$user->trash()` | `DELETE FROM users WHERE id = ?` | void |

## Próximos pasos

Ahora que comprendes VersaModel, puedes continuar con:
- [Manejo de Errores](manejo-errores.md) - Aprender a manejar excepciones
- [Query Builder](../04-query-builder/README.md) - Para consultas más complejas
- [Relaciones](../05-relaciones/README.md) - Conectar modelos entre sí
