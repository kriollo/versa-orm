# Uso Básico (Operaciones CRUD)

Una vez que hayas [configurado VersaORM](.../getting-started/configuration.md), puedes empezar a realizar operaciones básicas de base de datos: Crear, Leer, Actualizar y Eliminar (CRUD).

La forma más sencilla de interactuar con tus tablas es a través de `VersaModel`, que implementa el patrón **Active Record**. Esto significa que cada objeto de `VersaModel` corresponde a una fila en tu base de datos.

**Requisito previo:** Asegúrate de haber configurado la instancia global del ORM como se explica en la guía de configuración:

```php
// En tu archivo de arranque (p. ej., index.php)
use VersaORM\VersaORM;
use VersaORM\VersaModel;

$orm = new VersaORM($config);
VersaModel::setORM($orm); // ¡Importante para los ejemplos de esta página!
```

---

## 1. Crear Registros (Create)

Para crear un nuevo registro, primero "dispensas" un nuevo objeto `VersaModel` para la tabla deseada. Luego, asignas sus propiedades y finalmente lo guardas con el método `store()`.

Supongamos que tienes una tabla `users` con las columnas `name`, `email` y `status`.

```php
// 1. Dispensa un nuevo modelo para la tabla 'users'
$user = VersaModel::dispense('users');

// 2. Asigna valores a sus propiedades
$user->name = 'Juan Pérez';
$user->email = 'juan.perez@example.com';
$user->status = 'active';

// 3. Guarda el registro en la base de datos
$user->store();

// Después de guardar, el objeto se actualiza con el ID y otros valores por defecto
echo "Usuario creado con ID: " . $user->id;
```

`store()` ejecutará una consulta `INSERT` y automáticamente poblará el objeto `$user` con el `id` asignado por la base de datos y cualquier otro valor predeterminado (como `created_at`).

---

## 2. Leer Registros (Read)

VersaORM ofrece varios métodos para leer datos.

### Leer un solo registro por ID

El método `load()` te permite obtener un registro específico por su clave primaria.

```php
// Carga el usuario con ID = 1
$user = VersaModel::load('users', 1);

if ($user) {
    echo "Nombre: " . $user->name;    // "Juan Pérez"
    echo "Email: " . $user->email;   // "juan.perez@example.com"
} else {
    echo "Usuario no encontrado.";
}
```
`load()` devuelve un objeto `VersaModel` si lo encuentra, o `null` si no existe ningún registro con ese ID.

### Leer múltiples registros

Para obtener una colección de registros, puedes usar `findAll()`.

```php
// Obtener todos los usuarios
$allUsers = VersaModel::findAll('users');

foreach ($allUsers as $user) {
    echo $user->name . "\n";
}

// También puedes añadir condiciones WHERE simples
$activeUsers = VersaModel::findAll('users', 'status = ?', ['active']);

echo "Hay " . count($activeUsers) . " usuarios activos.";
```
`findAll()` devuelve un array de objetos `VersaModel`. Para consultas más complejas, deberías usar el [Query Builder](02-query-builder.md).

---

## 3. Actualizar Registros (Update)

Para actualizar un registro, primero cárgalo, luego modifica sus propiedades y finalmente vuelve a llamar a `store()`.

```php
// 1. Carga el registro que quieres modificar
$user = VersaModel::load('users', 1);

if ($user) {
    // 2. Modifica las propiedades
    $user->name = 'Juan Carlos Pérez';
    $user->status = 'inactive';

    // 3. Guarda los cambios
    $user->store();

    echo "Usuario actualizado.";
}
```

VersaORM es lo suficientemente inteligente como para saber que el objeto ya tiene un `id`, por lo que `store()` ejecutará una consulta `UPDATE` en lugar de un `INSERT`.

---

## 4. Eliminar Registros (Delete)

Para eliminar un registro, cárgalo y luego usa el método `trash()`.

```php
// 1. Carga el registro que quieres eliminar
$user = VersaModel::load('users', 1);

if ($user) {
    // 2. Elimina el registro de la base de datos
    $user->trash();

    echo "Usuario eliminado.";
}
```

Después de llamar a `trash()`, el objeto `$user` quedará vacío, ya que el registro correspondiente ya no existe en la base de datos.

---

## Exportar a Array

A menudo, necesitarás convertir los datos de un modelo a un array, por ejemplo, para generar una respuesta JSON en una API. Puedes usar el método `export()`.

```php
$user = VersaModel::load('users', 1);
$userData = $user->export();

// $userData es ahora un array asociativo:
// [
//   'id' => 1,
//   'name' => 'Juan Carlos Pérez',
//   'email' => 'juan.perez@example.com',
//   'status' => 'inactive',
//   'created_at' => '2024-07-29 10:00:00'
// ]

header('Content-Type: application/json');
echo json_encode($userData);
```

Para exportar un array de modelos, puedes usar el método estático `exportAll()`.

```php
$users = VersaModel::findAll('users');
$usersData = VersaModel::exportAll($users);

echo json_encode($usersData);
```

## Siguientes Pasos

Ahora que dominas las operaciones básicas, es hora de aprender a construir consultas más complejas con el **[Query Builder](02-query-builder.md)**.

```