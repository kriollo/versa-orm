# Guía del Query Builder

El Query Builder (Constructor de Consultas) de VersaORM es una de sus herramientas más potentes. Te permite construir consultas SQL complejas de una manera fluida, programática y segura, sin tener que escribir SQL a mano. Es ideal para reportes, búsquedas complejas y cualquier situación que vaya más allá de un simple CRUD.

Para empezar a construir una consulta, utiliza el método `table()` de tu instancia de ORM:

```php
$query = $orm->table('users'); // ¡Este es el punto de partida!
```

---

## Obteniendo Resultados: La Diferencia Clave

Antes de ver los métodos de construcción, es crucial entender cómo obtener los resultados. El Query Builder puede devolver los datos de dos formas distintas, diseñadas para diferentes casos de uso:

1.  **Como Arrays (`getAll`, `firstArray`)**: Devuelve arrays asociativos de PHP. **Ideal para APIs**, respuestas JSON o cuando solo necesitas los datos sin la sobrecarga de un objeto.

2.  **Como Objetos (`findAll`, `findOne`)**: Devuelve instancias de `VersaModel`. **Ideal para lógica de negocio**, donde quieres manipular los registros como objetos (p. ej., llamar a métodos del modelo, modificar y guardar).

| Caso de Uso                  | Método Recomendado | Devuelve                               |
| ---------------------------- | ------------------ | -------------------------------------- |
| Necesito datos para una API JSON | `getAll()`         | `array` de `array`s asociativos        |
| Necesito un solo registro (API)  | `firstArray()`     | `array` asociativo o `null`            |
| Necesito objetos para manipular  | `findAll()`        | `array` de objetos `VersaModel`        |
| Necesito un solo objeto para usar | `findOne()`        | Objeto `VersaModel` o `null`           |

---

## Construcción de la Consulta

Todos los métodos de construcción de consultas se pueden encadenar.

### `select()` - Especificar Columnas

Por defecto, una consulta selecciona todas las columnas (`*`). Puedes especificar cuáles necesitas con `select()`.

```php
// Seleccionar solo id, name y email
$users = $orm->table('users')
    ->select(['id', 'name', 'email'])
    ->getAll();

// Puedes usar alias
$products = $orm->table('products')
    ->select(['id', 'name as product_name'])
    ->getAll();
```

### `where()` - Cláusulas WHERE

El método `where()` es la forma más común de filtrar resultados. Por defecto, las condiciones se unen con `AND`.

```php
// WHERE status = 'active' AND age >= 18
$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->findAll();
```

#### `orWhere()`

Para unir condiciones con `OR`.

```php
// WHERE status = 'active' OR is_premium = 1
$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->orWhere('is_premium', '=', 1)
    ->findAll();
```

#### Otros Métodos `where`

- `whereIn(string $column, array $values)`: Filtra si el valor de una columna está en un array.
- `whereNotIn(string $column, array $values)`: El opuesto a `whereIn`.
- `whereNull(string $column)`: Filtra registros donde la columna es `NULL`.
- `whereNotNull(string $column)`: Filtra registros donde la columna no es `NULL`.
- `whereBetween(string $column, $min, $max)`: Filtra registros donde el valor de una columna está entre `$min` y `$max`.
- `whereRaw(string $sql, array $bindings = [])`: Añade una condición SQL cruda. ¡Úsalo con precaución!

**Ejemplo combinado:**

```php
$products = $orm->table('products')
    ->whereIn('category_id', [1, 2, 3])
    ->whereBetween('price', 100, 500)
    ->whereNotNull('published_at')
    ->whereRaw('stock > reserved_stock')
    ->getAll();
```

### `join()` - Unir Tablas

Puedes realizar uniones (`JOIN`) entre tablas fácilmente.

- `join(string $table, string $firstCol, string $operator, string $secondCol)`: `INNER JOIN`
- `leftJoin(...)`: `LEFT JOIN`
- `rightJoin(...)`: `RIGHT JOIN`

```php
// Obtener usuarios y los títulos de sus posts
$data = $orm->table('users')
    ->select(['users.name', 'posts.title as post_title'])
    ->join('posts', 'users.id', '=', 'posts.user_id')
    ->where('users.status', '=', 'active')
    ->getAll();
```

### Orden, Agrupación y Paginación

- `orderBy(string $column, string $direction = 'asc')`: Ordena los resultados.
- `groupBy(string|array $columns)`: Agrupa los resultados (útil para agregados).
- `limit(int $count)`: Limita el número de registros devueltos.
- `offset(int $count)`: Especifica desde qué registro empezar (para paginación).

**Ejemplo de paginación:**

```php
$page = 3;
$perPage = 10;

$users = $orm->table('users')
    ->orderBy('created_at', 'desc')
    ->limit($perPage)
    ->offset(($page - 1) * $perPage)
    ->findAll();
```

---

## Carga Ansiosa (Eager Loading) con `with()`

Cuando se trabaja con relaciones de modelos (ver la guía de Modelos y Objetos), es fácil caer en el "problema N+1": una consulta para el modelo principal y N consultas adicionales para cargar las relaciones de cada modelo. Esto es muy ineficiente.

VersaORM soluciona esto con la **carga ansiosa** a través del método `with()`. Este método le dice al ORM que cargue las relaciones especificadas junto con la consulta principal.

**Ejemplo del problema N+1 (MALO):**
```php
// Se ejecuta 1 consulta para obtener todos los posts
$posts = Post::findAll();

// Se ejecuta 1 consulta ADICIONAL por CADA post para obtener el autor
foreach ($posts as $post) {
  echo "Autor: " . $post->user->name; // <-- ¡Consulta aquí!
}
```

**Solución con `with()` (BUENO):**
```php
// Se ejecutan solo 2 consultas en total, sin importar cuántos posts haya.
$posts = $orm->table('posts')->with('user')->findAll();

foreach ($posts as $post) {
  echo "Autor: " . $post->user->name; // <-- No hay consulta aquí, los datos ya están cargados.
}
```

## Funciones de Agregado

El Query Builder también puede realizar consultas de agregado de forma eficiente.

- `count()`: Devuelve el número de registros que coinciden con la consulta.
- `exists()`: Devuelve `true` o `false` si existen registros que coincidan.

```php
// Contar cuántos usuarios inactivos hay
$inactiveCount = $orm->table('users')
    ->where('status', '=', 'inactive')
    ->count(); // Devuelve un entero, ej: 15

// Verificar si un email ya existe
$emailExists = $orm->table('users')
    ->where('email', '=', 'test@example.com')
    ->exists(); // Devuelve true o false
```

---

## Operaciones de Escritura (CRUD)

El Query Builder no es solo para leer. También puedes realizar operaciones de `INSERT`, `UPDATE` y `DELETE`, que son especialmente útiles para operaciones en masa.

### `insert()` e `insertGetId()`

```php
// Insertar un nuevo registro
$orm->table('logs')->insert([
    'level' => 'info',
    'message' => 'User logged in',
    'context' => json_encode(['user_id' => 123])
]);

// Insertar y obtener el ID del nuevo registro
$newUserId = $orm->table('users')->insertGetId([
    'name' => 'Nuevo Usuario',
    'email' => 'nuevo@example.com'
]);
```

### `update()`

El método `update()` actualiza los registros que coincidan con las cláusulas `where`.

```php
// Actualizar un usuario específico
$orm->table('users')
    ->where('id', '=', $newUserId)
    ->update(['status' => 'active']);

// Actualizar múltiples registros
// Poner todos los posts antiguos como archivados
$orm->table('posts')
    ->where('created_at', '<', '2023-01-01')
    ->update(['status' => 'archived']);
```

### `delete()`

El método `delete()` elimina los registros que coincidan con las cláusulas `where`.

```php
// Eliminar un usuario específico
$orm->table('users')
    ->where('id', '=', 10)
    ->delete();

// Eliminar todos los logs de nivel 'debug'
$orm->table('logs')
    ->where('level', '=', 'debug')
    ->delete();
```

## Siguientes Pasos

Ahora que sabes cómo construir todo tipo de consultas, aprende más sobre cómo trabajar con los resultados como objetos en la guía de **[Modelos y Objetos (VersaModel)](03-models-and-objects.md)**.
