# Relaciones Uno-a-Muchos (hasMany/belongsTo)

Esta es la relación más común, donde un modelo "padre" (como `User`) puede tener muchos modelos "hijos" (como `Post`), y cada hijo pertenece a un solo padre.

## 1. Definiendo la Relación

Para empezar, define los métodos de relación en ambos modelos. Recuerda usar el trait `HasRelationships`.

**Modelo `User` (El que "tiene muchos")**
```php
class User extends VersaModel
{
    use HasRelationships;
    protected string $table = 'users';

    public function posts()
    {
        // Un usuario TIENE MUCHOS posts
        return $this->hasMany(Post::class, 'user_id');
    }
}
```

**Modelo `Post` (El que "pertenece a")**
```php
class Post extends VersaModel
{
    use HasRelationships;
    protected string $table = 'posts';

    public function user()
    {
        // Un post PERTENECE A un usuario
        return $this->belongsTo(User::class, 'user_id');
    }
}
```

## 2. Creando Registros Relacionados

La relación `hasMany` proporciona un método `create()` que simplifica la creación de modelos hijos. Automáticamente asignará la clave foránea (`user_id`) por ti.

```php
// Cargar un usuario existente
$user = User::load(1);

// Crear un nuevo post para este usuario a través de la relación
$newPost = $user->posts()->create([
    'title' => 'Mi nuevo post con VersaORM',
    'content' => 'Crear relaciones es muy fácil.'
]);

echo "Post creado con ID: " . $newPost->id . " para el usuario: " . $user->name;
```

El método `create()` en la relación es la forma recomendada de crear registros asociados, ya que garantiza la integridad referencial.

## 3. Consultando la Relación (Lazy Loading)

Puedes acceder a los modelos relacionados como si fueran propiedades. VersaORM ejecutará la consulta necesaria la primera vez que accedas a ellos.

### Obtener los Posts de un Usuario (`hasMany`)

```php
$user = User::load(1);

// Acceder a la "propiedad" posts.
// La primera vez, VersaORM ejecuta: SELECT * FROM posts WHERE user_id = 1;
$posts = $user->posts;

foreach ($posts as $post) {
    echo "- " . $post->title . "\n";
}
```

### Obtener el Usuario de un Post (`belongsTo`)

```php
$post = Post::load(5);

// Acceder a la "propiedad" user.
// La primera vez, VersaORM ejecuta: SELECT * FROM users WHERE id = [post.user_id];
$author = $post->user;

echo "El post '" . $post->title . "' fue escrito por " . $author->name . ".";
```

> **⚠️ ¡Cuidado con el problema N+1!**
> El Lazy Loading es muy cómodo, pero si iteras sobre una colección y accedes a una relación en cada iteración (ej. mostrar el autor de cada post en una lista), generarás una consulta por cada item. 
> Para solucionar esto, consulta nuestra guía sobre **[Carga Eficiente (Eager Loading)](eager-loading.md)**.

## 4. Consultas sobre la Relación

Puedes añadir condiciones adicionales a tus consultas de relación antes de obtener los resultados.

```php
$user = User::load(1);

// Obtener solo los posts publicados de este usuario
$publishedPosts = $user->posts()->where('published', '=', true)->findAll();

// Contar cuántos borradores tiene
$draftCount = $user->posts()->where('published', '=', false)->count();

echo "El usuario tiene " . $draftCount . " borradores.";
```

