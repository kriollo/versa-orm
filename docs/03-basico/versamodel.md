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
$model = VersaModel::dispense("table_name");
```

**Devuelve:** Objeto VersaModel vacío

### Ejemplos prácticos

```php
// Crear un nuevo usuario
$user = VersaModel::dispense('users');
echo get_class($user); // VersaORM\VersaModel
echo $user->id; // null (aún no tiene ID)

// Asignar propiedades
$user->name = 'Pedro Sánchez';
$user->email = 'pedro@ejemplo.com';
$user->active = true;

// En este punto el usuario existe solo en memoria
// No se ha guardado en la base de datos aún
```

### Crear múltiples modelos

```php
// Crear varios modelos de una vez
$users = [];
for ($i = 0; $i < 3; $i++) {
    $users[] = VersaModel::dispense('users');
}

$users[0]->name = 'Usuario 1';
$users[1]->name = 'Usuario 2';
$users[2]->name = 'Usuario 3';

// Todos están en memoria, no en la base de datos
```

**SQL Equivalente:** No hay equivalente directo, ya que `dispense()` no ejecuta SQL.

## load() - Cargar modelos existentes

El método `load()` recupera un registro existente de la base de datos y lo convierte en un objeto VersaModel.

### Sintaxis básica

```php
$model = VersaModel::load('table_name', $id);
```

**Devuelve:** Objeto VersaModel o null si no existe el registro

### Ejemplos prácticos

```php
// Cargar usuario por ID
$user = VersaModel::load('users', 1);

if ($user !== null) {
    echo "Usuario encontrado: " . $user->name;
    echo "Email: " . $user->email;
    echo "Activo: " . ($user->active ? 'Sí' : 'No');
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
$user = VersaModel::load('users', 999);

if ($user !== null) {
    echo "El usuario existe";
} else {
    echo "El usuario no existe";
}

// También puedes verificar directamente
if ($user === null) {
    echo "El modelo no existe en BD";
}
```

### Cargar con valores por defecto

```php
// Si el usuario no existe, crear uno nuevo con valores por defecto
$user = VersaModel::load('users', 999);

if ($user === null) {
    $user = VersaModel::dispense('users');
    $user->name = 'Usuario por defecto';
    $user->email = 'default@ejemplo.com';
    $user->active = false;
}
```

## store() - Guardar modelos

El método `store()` guarda un modelo en la base de datos. Automáticamente determina si debe hacer INSERT (crear) o UPDATE (actualizar).

### Sintaxis básica

```php
$model->store();
```

**Devuelve:** El modelo con ID asignado (si es nuevo)

### Crear nuevo registro (INSERT)

```php
// Crear nuevo usuario
$user = VersaModel::dispense('users');
$user->name = 'Laura González';
$user->email = 'laura@ejemplo.com';
$user->active = true;

$user->store();
echo "Usuario creado con ID: " . $user->id;

// Después del store(), el modelo tiene ID asignado automáticamente
echo "ID del modelo: " . $user->id;
```

**SQL Equivalente:**
```sql
INSERT INTO users (name, email, active) VALUES ('Laura González', 'laura@ejemplo.com', 1);
```

### Actualizar registro existente (UPDATE)

```php
// Cargar usuario existente
$user = VersaModel::load('users', 1);

if ($user !== null) {
    // Modificar propiedades
    $user->name = 'Laura María González';
    $user->email = 'lauramaria@ejemplo.com';

    $user->store();
    echo "Usuario actualizado. ID: " . $user->id;
}
```

**SQL Equivalente:**
```sql
UPDATE users SET name = 'Laura María González', email = 'lauramaria@ejemplo.com' WHERE id = 1;
```

### Guardar múltiples modelos

```php
// Crear varios usuarios
$users = [];

$user1 = VersaModel::dispense('users');
$user1->name = 'Usuario A';
$user1->email = 'a@ejemplo.com';
$users[] = $user1;

$user2 = VersaModel::dispense('users');
$user2->name = 'Usuario B';
$user2->email = 'b@ejemplo.com';
$users[] = $user2;

// Guardar todos de una vez
// Devuelve array de IDs en orden
$ids = VersaModel::storeAll($users);
echo "IDs creados: " . implode(', ', $ids);
```

**Devuelve:** Array de IDs (int|string|null)

## trash() - Eliminar modelos

El método `trash()` elimina un modelo de la base de datos.

### Sintaxis básica

```php
$model->trash();
```

**Devuelve:** void (no devuelve valor)

### Ejemplos prácticos

```php
// Cargar y eliminar usuario
$user = VersaModel::load('users', 1);

if ($user !== null) {
    $user->trash();
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
$inactiveUsers = VersaModel::findAll('users', 'active = ?', [false]);

foreach ($inactiveUsers as $user) {
    $user->trash();
}

echo "Eliminados " . count($inactiveUsers) . " usuarios";

// O usar trashAll para eliminar múltiples (usalo con precaución)
VersaModel::trashAll($inactiveUsers);
```

## Propiedades y métodos útiles de VersaModel

### Verificar estado del modelo

```php
$user = VersaModel::load('users', 1);

// Verificar si el modelo existe en la base de datos
if ($user !== null) {
    echo "El modelo tiene ID, existe en BD";
}

// Verificar si el modelo está vacío
if ($user->isEmpty()) {
    echo "El modelo está vacío";
}

// Obtener el nombre de la tabla
echo $user->getMeta('type'); // 'users'
```

### Acceder a propiedades

```php
$user = VersaModel::load('users', 1);

// Acceso directo a propiedades
echo $user->name;
echo $user->email;

// Verificar si una propiedad existe
if (isset($user->phone)) {
    echo "Teléfono: " . $user->phone;
}

// Obtener todas las propiedades como array
$data = $user->export();
print_r($data);
```

### Modificar propiedades

```php
$user = VersaModel::load('users', 1);

// Asignación directa
$user->name = 'Nuevo nombre';
$user->email = 'nuevo@email.com';

// Asignación condicional
if (!$user->phone) {
    $user->phone = '123-456-7890';
}

// Guardar cambios
$user->store();
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
    $product = VersaModel::dispense('products');
    echo "Modelo creado. ID: " . ($product->id ?? 'null') . "\n";
    echo "¿Está vacío? " . ($product->isEmpty() ? 'Sí' : 'No') . "\n\n";

    echo "=== Asignar propiedades ===\n";
    $product->name = 'Laptop Dell';
    $product->price = 899.99;
    $product->category = 'Electronics';
    $product->in_stock = true;
    echo "Propiedades asignadas\n\n";

    echo "=== STORE: Guardar modelo (INSERT) ===\n";
    $id = $product->store();
    echo "Producto guardado con ID: $id\n";
    echo "ID del modelo: " . $product->id . "\n\n";

    echo "=== LOAD: Cargar modelo existente ===\n";
    $readProduct = VersaModel::load('products', $id);
    echo "Producto cargado: " . $readProduct->name . "\n";
    echo "Precio: $" . $readProduct->price . "\n\n";

    echo "=== Modificar y STORE: Actualizar (UPDATE) ===\n";
    $readProduct->price = 799.99;
    $readProduct->on_sale = true;
    $updatedId = $readProduct->store();
    echo "Producto actualizado. ID: $updatedId\n\n";

    echo "=== Verificar actualización ===\n";
    $updatedProduct = VersaModel::load('products', $id);
    echo "Nuevo precio: $" . $updatedProduct->price . "\n";
    echo "En oferta: " . ($updatedProduct->on_sale ? 'Sí' : 'No') . "\n\n";

    echo "=== TRASH: Eliminar modelo ===\n";
    $updatedProduct->trash();
    echo "Producto eliminado\n";
    echo "ID después de eliminar: " . ($updatedProduct->id ?? 'null') . "\n\n";

    echo "=== Verificar eliminación ===\n";
    $deletedProduct = VersaModel::load('products', $id);
    if ($deletedProduct->isEmpty()) {
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
$user = VersaModel::load('users', $id);
if ($user !== null) {
    $user->name = 'Nuevo nombre';
    $user->store();
}

// ❌ Incorrecto
$user = VersaModel::load('users', $id);
$user->name = 'Nuevo nombre'; // Error si no existe
$user->store();
```

### 2. Usar nombres de tabla consistentes

```php
// ✅ Correcto - usar nombres en plural
$user = VersaModel::dispense('users');
$product = VersaModel::dispense('products');

// ❌ Evitar - inconsistencia
$user = VersaModel::dispense('user');
$product = VersaModel::dispense('products');
```

### 3. Validar datos antes de guardar

```php
$user = VersaModel::dispense('users');
$user->name = trim($name);

// Validar email
if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $user->email = $email;
} else {
    throw new InvalidArgumentException('Email inválido');
}

$user->store();
```

### 4. Manejar modelos vacíos apropiadamente

```php
$user = VersaModel::load('users', $id);

if ($user->isEmpty()) {
    // Crear nuevo usuario si no existe
    $user = VersaModel::dispense('users');
    $user->name = 'Usuario por defecto';
}

$user->store();
```

## Comparación con SQL tradicional

| Operación VersaORM | SQL Equivalente | Devuelve |
|-------------------|-----------------|
| `VersaModel::dispense('users')` | N/A (solo en memoria) | VersaModel vacío |
| `VersaModel::load('users', 1)` | `SELECT * FROM users WHERE id = 1` | VersaModel |
| `$user->store()` (nuevo) | `INSERT INTO users (...)` | ID (integer) |
| `$user->store()` (existente) | `UPDATE users SET ... WHERE id = ?` | ID (integer) |
| `$user->trash()` | `DELETE FROM users WHERE id = ?` | void |

## Próximos pasos

Ahora que comprendes VersaModel, puedes continuar con:
- [Manejo de Errores](manejo-errores.md) - Aprender a manejar excepciones
- [Query Builder](../04-query-builder/README.md) - Para consultas más complejas
- [Relaciones](../05-relaciones/README.md) - Conectar modelos entre sí
