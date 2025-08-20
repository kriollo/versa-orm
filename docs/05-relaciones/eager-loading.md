# Carga Eficiente de Relaciones (Eager Loading)

Por defecto, VersaORM utiliza **Lazy Loading** (carga perezosa): las relaciones solo se cargan de la base de datos cuando accedes a ellas por primera vez. Esto es simple, pero puede causar serios problemas de rendimiento en bucles, un problema conocido como **"N+1"**.

## El Problema N+1

Imagina que quieres mostrar una lista de posts y el nombre del autor de cada uno.

```php
// 1ª consulta: para obtener todos los posts.
$posts = Post::findAll();

foreach ($posts as $post) {
    // ❌ PROBLEMA: Se ejecuta 1 consulta adicional POR CADA post para obtener su autor.
    echo $post->title . ' por ' . $post->user->name . '\n';
}
```

Si tienes 100 posts, este código ejecutará **101 consultas** (1 para los posts + 100 para los autores). Esto es extremadamente ineficiente.

## La Solución: Eager Loading con `with()`

Para resolver esto, VersaORM proporciona el método `with()`. Le indica al ORM que cargue las relaciones especificadas de antemano, reduciendo cientos de consultas a solo un par.

`with()` funciona de la siguiente manera:
1.  Ejecuta la consulta principal (ej. para obtener los posts).
2.  Recopila los IDs necesarios de los resultados (ej. todos los `user_id`).
3.  Ejecuta una **única consulta adicional** para cargar todos los modelos relacionados (ej. `SELECT * FROM users WHERE id IN (...)`).
4.  Asocia los modelos en memoria, eficientemente.

### Eager Loading de Relaciones

```php
// ✅ SOLUCIÓN: Solo 2 consultas, sin importar la cantidad de posts.
$posts = $orm->table('posts', Post::class)
             ->with('user') // ¡Precargar la relación 'user'!
             ->findAll();

foreach ($posts as $post) {
    // No se ejecuta ninguna consulta aquí, el autor ya fue cargado.
    echo $post->title . ' por ' . $post->user->name . '\n';
}
```

### Eager Loading de Múltiples Relaciones

Puedes cargar varias relaciones a la vez pasando un array.

```php
// Cargar posts con su autor y sus comentarios
$posts = $orm->table('posts', Post::class)
             ->with(['user', 'comments']) // Cargar múltiples relaciones
             ->findAll(); // Esto generará solo 3 consultas en total
```

### Eager Loading de Relaciones Anidadas

Usa la notación de punto para cargar relaciones de relaciones.

```php
// Cargar usuarios, sus posts, y los comentarios de CADA post
$users = $orm->table('users', User::class)
             ->with(['posts.comments']) // Cargar relación anidada
             ->findAll(); // Generará 3 consultas en total
```

## Resumen de Estrategias

| Estrategia    | Cuándo Usarla                                                              | Ventajas                               | Desventajas                                     |
|---------------|----------------------------------------------------------------------------|----------------------------------------|-------------------------------------------------|
| **Lazy Loading** (por defecto) | Cuando trabajas con un **único objeto** o sabes que **no siempre** necesitarás la relación. | Simple, carga datos solo si son necesarios. | Causa el problema N+1 en bucles.                |
| **Eager Loading** (`with()`)   | **Siempre** que iteres sobre una colección de objetos y sepas que vas a necesitar sus relaciones. | **Soluciona el problema N+1**. Altamente eficiente. | Carga datos que podrían no usarse si la lógica es condicional. |

> **Regla de oro:** Si estás escribiendo un `foreach` y dentro accedes a una relación, necesitas `with()`.