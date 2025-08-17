# Tipos de Relaciones

Las relaciones en bases de datos representan cómo las tablas se conectan entre sí. VersaORM facilita el trabajo con estas relaciones mediante métodos intuitivos que abstraen la complejidad del SQL.

## Conceptos Fundamentales

### ¿Qué es una Relación?

Una relación es una asociación lógica entre dos o más tablas que permite conectar datos relacionados. Por ejemplo:

- Un **usuario** puede tener muchos **posts**
- Un **post** pertenece a un **usuario**
- Un **post** puede tener muchos **tags**, y un **tag** puede estar en muchos **posts**

### Claves Foráneas

Las relaciones se implementan mediante **claves foráneas** (foreign keys):

```sql
-- Tabla users
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL
);

-- Tabla posts con clave foránea
CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    user_id INT,  -- ← Clave foránea que referencia users.id
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## Tipos de Relaciones

### 1. Uno-a-Uno (One-to-One)

Cada registro en la tabla A se relaciona con exactamente un registro en la tabla B.

**Ejemplo:** Usuario ↔ Perfil

```
users          profiles
┌─────┬──────┐  ┌─────┬─────────┬─────────┐
│ id  │ name │  │ id  │ user_id │ bio     │
├─────┼──────┤  ├─────┼─────────┼─────────┤
│ 1   │ Juan │  │ 1   │ 1       │ "..."   │
│ 2   │ Ana  │  │ 2   │ 2       │ "..."   │
└─────┴──────┘  └─────┴─────────┴─────────┘
```

**En VersaORM:**
```php
// En el modelo User
public function profile() {
    return $this->hasOne('profile', 'user_id');
}

// En el modelo Profile
public function user() {
    return $this->belongsTo('user', 'user_id');
}
```

### 2. Uno-a-Muchos (One-to-Many)

Un registro en la tabla A puede relacionarse con múltiples registros en la tabla B.

**Ejemplo:** Usuario → Posts

```
users          posts
┌─────┬──────┐  ┌─────┬─────────┬─────────┐
│ id  │ name │  │ id  │ user_id │ title   │
├─────┼──────┤  ├─────┼─────────┼─────────┤
│ 1   │ Juan │  │ 1   │ 1       │ "Post1" │
│ 2   │ Ana  │  │ 2   │ 1       │ "Post2" │
└─────┴──────┘  │ 3   │ 2       │ "Post3" │
                └─────┴─────────┴─────────┘
```

**En VersaORM:**
```php
// En el modelo User
public function posts() {
    return $this->hasMany('post', 'user_id');
}

// En el modelo Post
public function user() {
    return $this->belongsTo('user', 'user_id');
}
```

### 3. Muchos-a-Muchos (Many-to-Many)

Múltiples registros en la tabla A pueden relacionarse con múltiples registros en la tabla B.

**Ejemplo:** Posts ↔ Tags

```
posts          post_tags       tags
┌─────┬───────┐ ┌─────────┬────────┐ ┌─────┬──────────┐
│ id  │ title │ │ post_id │ tag_id │ │ id  │ name     │
├─────┼───────┤ ├─────────┼────────┤ ├─────┼──────────┤
│ 1   │ "P1"  │ │ 1       │ 1      │ │ 1   │ "PHP"    │
│ 2   │ "P2"  │ │ 1       │ 2      │ │ 2   │ "MySQL"  │
└─────┴───────┘ │ 2       │ 1      │ │ 3   │ "Web"    │
                │ 2       │ 3      │ └─────┴──────────┘
                └─────────┴────────┘
```

**En VersaORM:**
```php
// En el modelo Post
public function tags() {
    return $this->belongsToMany('tag', 'post_tags', 'post_id', 'tag_id');
}

// En el modelo Tag
public function posts() {
    return $this->belongsToMany('post', 'post_tags', 'tag_id', 'post_id');
}
```

## Convenciones de Nomenclatura

VersaORM sigue convenciones que simplifican la definición de relaciones:

### Nombres de Tablas
- Singular en minúsculas: `user`, `post`, `tag`
- Para tablas pivot: `tabla1_tabla2` en orden alfabético: `post_tags`

### Claves Foráneas
- Formato: `{tabla_singular}_id`
- Ejemplos: `user_id`, `category_id`, `product_id`

### Métodos de Relación
- `hasOne()`: Relación uno-a-uno (lado propietario)
- `belongsTo()`: Relación uno-a-uno/muchos (lado dependiente)
- `hasMany()`: Relación uno-a-muchos (lado propietario)
- `belongsToMany()`: Relación muchos-a-muchos

## Ejemplo Práctico Completo

Veamos un ejemplo con las tablas de nuestro sistema de ejemplo:

```php
<?php
require_once 'vendor/autoload.php';

// Configuración
$orm = new VersaORM();
$orm->setup('mysql:host=localhost;dbname=ejemplo', 'usuario', 'password');

// Crear un usuario con posts
$user = VersaModel::dispense('user');
$user->name = 'María García';
$user->email = 'maria@ejemplo.com';
$userId = $user->store();

// Crear posts para el usuario
$post1 = VersaModel::dispense('post');
$post1->title = 'Mi primer post';
$post1->content = 'Contenido del primer post';
$post1->user_id = $userId;
$post1->store();

$post2 = VersaModel::dispense('post');
$post2->title = 'Segundo post';
$post2->content = 'Más contenido interesante';
$post2->user_id = $userId;
$post2->store();

// Obtener usuario con sus posts
$userWithPosts = VersaModel::load('user', $userId);
echo "Usuario: " . $userWithPosts->name . "\n";

// Obtener posts del usuario (esto se explica en detalle en la siguiente sección)
$posts = VersaModel::findAll('post', 'user_id = ?', [$userId]);
foreach ($posts as $post) {
    echo "- " . $post->title . "\n";
}
```

**Salida:**
```
Usuario: María García
- Mi primer post
- Segundo post
```

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