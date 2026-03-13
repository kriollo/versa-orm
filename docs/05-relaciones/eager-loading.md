
# Carga Eficiente de Relaciones (Eager Loading)

VersaORM soporta una **API dual para relaciones**:
- **Acceso por propiedad**: `$modelo->relacion` (lazy/eager loading, retorna resultados)
- **Acceso por método**: `$modelo->relacion()` (retorna el objeto de relación, permite encadenar QueryBuilder)

Esto permite escribir código flexible y expresivo, optimizando tanto la legibilidad como el rendimiento.


## El Problema N+1

Imagina que quieres mostrar una lista de posts y el nombre del autor de cada uno:

```php
$posts = Post::findAll();
foreach ($posts as $post) {
    // ❌ PROBLEMA: Se ejecuta 1 consulta adicional POR CADA post para obtener su autor.
    echo $post->title . ' por ' . $post->user->name . "\n";
}
```

Si tienes 100 posts, este código ejecutará **101 consultas** (1 para los posts + 100 para los autores). Esto es ineficiente y puede saturar la base de datos.


## La Solución Moderna: Eager Loading con `with()` y QueryBuilder en relaciones

VersaORM resuelve el problema N+1 con el método `with()`, que precarga las relaciones necesarias en una sola consulta adicional. Además, puedes combinar eager loading con la nueva API de relaciones para consultas avanzadas:

`with()` funciona así:
1. Ejecuta la consulta principal (ej. obtener los posts).
2. Recopila los IDs necesarios (ej. todos los `user_id`).
3. Ejecuta una única consulta adicional para cargar los modelos relacionados.
4. Asocia los modelos en memoria, eficientemente.


### Ejemplo clásico de eager loading
```php
// Solo 2 consultas, sin importar la cantidad de posts
$posts = $orm->table('posts', Post::class)
    ->with('user')
    ->findAll();
foreach ($posts as $post) {
    echo $post->title . ' por ' . $post->user->name . "\n"; // El autor ya fue cargado
}
```

### Ejemplo moderno: encadenamiento sobre relaciones precargadas
```php
$posts = $orm->table('posts', Post::class)
    ->with('user')
    ->findAll();

// Filtrar autores por condición usando la API dual
$activos = array_filter($posts, fn($p) => $p->user->activo);

// Usar QueryBuilder sobre la relación precargada
$primerAutor = $posts[0]->user()->where('activo', true)->firstArray();
```


### Eager Loading de múltiples y anidadas
```php
// Precargar autor y comentarios
$posts = $orm->table('posts', Post::class)
    ->with(['user', 'comments'])
    ->findAll(); // Solo 3 consultas

// Precargar relaciones anidadas
$users = $orm->table('users', User::class)
    ->with(['posts.comments'])
    ->findAll(); // Solo 3 consultas
```

### Eager Loading de Relaciones Anidadas

Usa la notación de punto para cargar relaciones de relaciones.

```php
// Cargar usuarios, sus posts, y los comentarios de CADA post
$users = $orm->table('users', User::class)
             ->with(['posts.comments']) // Cargar relación anidada
             ->findAll(); // Generará 3 consultas en total
```


## Resumen de Estrategias y API dual

| Estrategia    | Cuándo Usarla                                                              | Ventajas                               | Desventajas                                     |
|---------------|----------------------------------------------------------------------------|----------------------------------------|-------------------------------------------------|
| **Lazy Loading** (por defecto) | Cuando trabajas con un **único objeto** o sabes que **no siempre** necesitarás la relación. | Simple, carga datos solo si son necesarios. | Causa el problema N+1 en bucles.                |
| **Eager Loading** (`with()`)   | **Siempre** que iteres sobre una colección y accedas a relaciones en el bucle. | Soluciona el problema N+1, eficiente. | Puede cargar datos que no uses si la lógica es condicional. |

> **Regla de oro:** Si usas un `foreach` y accedes a una relación, usa `with()`. Si necesitas consultas avanzadas sobre la relación, usa el método: `$modelo->relacion()->where(...)->count()`.
