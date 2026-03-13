# Tipos de Relaciones

Las relaciones en bases de datos representan cómo las tablas se conectan entre sí. VersaORM facilita el trabajo con estas relaciones mediante métodos intuitivos que abstraen la complejidad del SQL.

## 1. Uno-a-Uno (hasOne / belongsTo)

Cada registro en la tabla A se relaciona con un único registro en la tabla B. Es la relación más simple.

- **Ejemplo**: Un `User` tiene un `Profile`.
- **Clave Foránea**: La tabla `profiles` contiene una `user_id`.

```
users          profiles
┌─────┬──────┐  ┌─────┬─────────┬─────────┐
│ id  │ name │  │ id  │ user_id │ bio     │
├─────┼──────┤  ├─────┼─────────┼─────────┤
│ 1   │ Juan │  │ 1   │ 1       │ "..."   │
└─────┴──────┘  └─────┴─────────┴─────────┘
```

**Definición en los Modelos:**

```php
// En el modelo User
public function profile()
{
    return $this->hasOne(Profile::class, 'user_id');
}

// En el modelo Profile
public function user()
{
    return $this->belongsTo(User::class, 'user_id');
}
```

## 2. Uno-a-Muchos (hasMany / belongsTo)

Un registro en la tabla A puede relacionarse con múltiples registros en la tabla B. Es la relación más común.

- **Ejemplo**: Un `User` tiene muchos `Posts`.
- **Clave Foránea**: La tabla `posts` contiene una `user_id`.

```
users          posts
┌─────┬──────┐  ┌─────┬─────────┬─────────┐
│ id  │ name │  │ id  │ user_id │ title   │
├─────┼──────┤  ├─────┼─────────┼─────────┤
│ 1   │ Juan │  │ 1   │ 1       │ "Post1" │
└─────┴──────┘  │ 2   │ 1       │ "Post2" │
                └─────┴─────────┴─────────┘
```

**Definición en los Modelos:**

```php
// En el modelo User
public function posts()
{
    return $this->hasMany(Post::class, 'user_id');
}

// En el modelo Post
public function user()
{
    return $this->belongsTo(User::class, 'user_id');
}
```

## 3. Muchos-a-Muchos (belongsToMany)

Múltiples registros en la tabla A pueden relacionarse con múltiples registros en la tabla B. Esta relación siempre requiere una **tabla intermedia (pivot)**.

- **Ejemplo**: Un `Post` tiene muchos `Tags`, y un `Tag` pertenece a muchos `Posts`.
- **Tabla Pivot**: `post_tag` con las columnas `post_id` y `tag_id`.

```
posts          post_tag       tags
┌─────┬───────┐ ┌─────────┬────────┐ ┌─────┬──────────┐
│ id  │ title │ │ post_id │ tag_id │ │ id  │ name     │
├─────┼───────┤ ├─────────┼────────┤ ├─────┼──────────┤
│ 1   │ "P1"  │ │ 1       │ 1      │ │ 1   │ "PHP"    │
└─────┴───────┘ │ 1       │ 2      │ │ 2   │ "MySQL"  │
                │ 2       │ 1      │ └─────┴──────────┘
                └─────────┴────────┘
```

**Definición en los Modelos:**

```php
// En el modelo Post
public function tags()
{
    return $this->belongsToMany(Tag::class, 'post_tag', 'post_id', 'tag_id');
}

// En el modelo Tag
public function posts()
{
    return $this->belongsToMany(Post::class, 'post_tag', 'tag_id', 'post_id');
}
```

## Convenciones de Nomenclatura

VersaORM utiliza convenciones para simplificar las definiciones. Si las sigues, no necesitarás especificar todos los argumentos en los métodos de relación.

- **Nombres de Tablas**: Plural y en `snake_case` (ej. `users`, `blog_posts`).
- **Tabla Pivot**: Nombres de los modelos en singular, en orden alfabético, separados por guion bajo (ej. `post_tag`, `role_user`).
- **Claves Foráneas**: Nombre del modelo en singular seguido de `_id` (ej. `user_id`).

Al seguir estas convenciones, el código se vuelve más limpio y consistente.

## Ventajas de las Relaciones en VersaORM

1. **Simplicidad**: Sintaxis intuitiva para definir y usar relaciones
2. **Flexibilidad**: Soporte para todos los tipos de relaciones
3. **Optimización**: Carga eficiente de datos relacionados
4. **Mantenibilidad**: Código más limpio y fácil de entender

## Próximos Pasos

En las siguientes secciones aprenderemos:

- Cómo implementar relaciones uno-a-muchos con `hasMany` y `belongsTo`
- Manejo de relaciones muchos-a-muchos con tablas pivot
- Estrategias de carga (lazy vs eager loading) para optimizar el rendimiento

## Navegación

- ← [README de Relaciones](README.md)
- → [Relaciones hasMany/belongsTo](hasMany-belongsTo.md)
