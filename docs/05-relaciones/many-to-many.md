# Relaciones Muchos-a-Muchos (belongsToMany)


Una relación muchos-a-muchos requiere una tabla intermedia (o **tabla pivot**) para funcionar. VersaORM automatiza la **consulta** de estas relaciones y, desde la versión actual, también permite gestionar las asociaciones directamente desde el objeto de relación (`BelongsToMany`).

## ¿Cómo se conecta la tabla pivot?

Cuando defines la relación en tu modelo usando `belongsToMany`, VersaORM sabe cómo conectar la tabla principal, la tabla relacionada y la tabla pivot. Por ejemplo:

```php
class User extends VersaModel {
    public function roles() {
        // roles: tabla relacionada, role_user: tabla pivot, user_id: clave local, role_id: clave relacionada
        return $this->belongsToMany(Role::class, 'role_user', 'user_id', 'role_id');
    }
}

class Role extends VersaModel {
    public function users() {
        return $this->belongsToMany(User::class, 'role_user', 'role_id', 'user_id');
    }
}
```

Esto permite que el objeto de relación (`$user->roles()`) tenga acceso a métodos para gestionar la tabla pivot.

## 1. Definiendo la Relación

Primero, define la relación `belongsToMany` en ambos modelos. Esto es crucial para que VersaORM sepa cómo construir las consultas para leer los datos.

**Modelo `Post`**
```php
class Post extends VersaModel
{
    use HasRelationships;
    protected string $table = 'posts';

    public function tags()
    {
        // ModeloRelacionado, tabla_pivot, clave_local_en_pivot, clave_relacionada_en_pivot
        return $this->belongsToMany(Tag::class, 'post_tag', 'post_id', 'tag_id');
    }
}
```

**Modelo `Tag`**
```php
class Tag extends VersaModel
{
    use HasRelationships;
    protected string $table = 'tags';

    public function posts()
    {
        return $this->belongsToMany(Post::class, 'post_tag', 'tag_id', 'post_id');
    }
}
```

## 2. Consultando la Relación (La Parte Automática)


Una vez definida la relación, puedes acceder a los modelos relacionados como una propiedad. VersaORM se encarga del `JOIN` con la tabla pivot:

```php
$user = User::findOne(2);
$roles = $user->roles; // Obtiene los roles del usuario 2
foreach ($roles as $role) {
    echo $role->name;
}
```

> **Rendimiento**: Usa **[Eager Loading](eager-loading.md)** (`->with('roles')`) para evitar el problema N+1.

## 3. Gestionando Asociaciones (La Parte Manual)


Ahora puedes gestionar las asociaciones directamente desde el objeto de relación:

### Añadir una Asociación (`attach`)

Agrega una relación en la tabla pivot si no existe:

```php
$user = User::findOne(2);
$user->roles()->attach(3); // Asocia el usuario 2 con el rol 3
```

### Eliminar una Asociación (`detach`)

Elimina una relación específica o todas las relaciones del modelo en la tabla pivot:

```php
$user = User::findOne(2);
$user->roles()->detach(3); // Elimina la asociación usuario 2 - rol 3
$user->roles()->detach();   // Elimina todas las asociaciones del usuario 2
```

### Sincronizar Asociaciones (`sync`)

Deja solo las asociaciones indicadas, eliminando las demás:

```php
$user = User::findOne(2);
$user->roles()->sync([3, 4]); // El usuario 2 solo tendrá los roles 3 y 4
$user = $user->fresh(); // Recarga el modelo y sus relaciones
$roles = $user->roles; // Accede a los roles actualizados
```

### Refrescar el modelo y sus relaciones (`fresh()`)

Para recargar el modelo y obtener los datos actualizados de la tabla pivot, **debes reasignar la instancia**:

```php
$user = User::findOne(2);
$user = $user->fresh(); // Recarga el usuario desde la base de datos
$roles = $user->roles; // Accede a los roles actualizados
```

## Resumen y Mejores Prácticas


- **Define siempre la relación `belongsToMany`** en tus modelos. Es indispensable para consultar y gestionar asociaciones.
- **Consulta** los datos usando la propiedad mágica (`$user->roles`).
- **Gestiona** las asociaciones usando los métodos `attach`, `detach`, `sync` directamente en el objeto de relación (`$user->roles()`).
- **Refresca** el modelo con `fresh()` **reasignando la instancia** (`$user = $user->fresh()`) para obtener los datos actualizados de la tabla pivot y sus relaciones.
- **Usa transacciones** al sincronizar para mantener la integridad de los datos (el método `sync` ya lo hace internamente).

## Próximos Pasos

En la siguiente sección aprenderemos sobre estrategias de carga (eager loading vs lazy loading) para optimizar el rendimiento cuando trabajamos con relaciones.

## Navegación

- ← [Relaciones hasMany/belongsTo](hasMany-belongsTo.md)
- → [Carga Eager vs Lazy](eager-loading.md)
