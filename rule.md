versaORM-PHP — ORM de alto rendimiento para PHP con núcleo en Rust

## Características

- ORM de alto rendimiento para PHP con núcleo en Rust
- ORM modular, seguro y ultrarrápido para PHP, desarrollado en Rust
- Devuelve respuestas tipadas correctamente, gestiona conexiones y relaciones con eficiencia y permite su uso como extensión PHP o binario externo
- Inspirado en lo mejor de RedBeanPHP, Eloquent y Doctrine

## Compatibilidad

- Sistemas operativos: Windows, macOS, Linux
- Lenguaje núcleo: Rust
- Lenguaje interfaz: PHP 7.4+
- Bases de datos soportadas: MySQL, PostgreSQL, SQLite

## Objetivo

Resolver la limitación principal de los ORMs en PHP:

- Datos retornados como string sin tipado.
- Overhead excesivo de frameworks grandes.
- Falta de rendimiento en entornos de alta carga.

## Características

| Característica              | Descripción                                                                               |
| --------------------------- | ----------------------------------------------------------------------------------------- |
| 🔄 Tipado correcto          | Devuelve `int`, `float`, `bool`, `null`, `string` según corresponda, no todo como string. |
| ⚡ Núcleo en Rust           | Máximo rendimiento, mínima memoria.                                                       |
| 🧱 Modular y extensible     | Arquitectura basada en módulos independientes.                                            |
| 🔍 Introspección de esquema | Lee estructura de tablas automáticamente.                                                 |
| 🔗 Relaciones ORM           | Soporte completo para relaciones `hasOne`, `hasMany`, `belongsTo`, `belongsToMany`.       |
| 🧠 Caching inteligente      | Caching de consultas y esquema.                                                           |
| 🔐 Seguro por diseño        | Queries preparadas, sin SQL Injection.                                                    |

Módulos y funcionalidades
🧩 Connection
Manejo de conexiones a la base de datos y drivers soportados.
VersaORM::connect(array $config): bool;
VersaORM::isConnected(): bool;
VersaORM::disconnect(): void;

- connect recibe un arreglo con credenciales: host, puerto, usuario, contraseña, base de datos.
- Conexión usa pooling si está disponible.
- get_driver() retorna el driver en uso ("mysql", "pgsql", etc).

🧱 QueryBuilder
Permite construir consultas dinámicas y encadenadas desde PHP. La salida siempre será un JSON con tipado de datos correcto.

**Ejemplo de uso en PHP:**
```php
$users = VersaORM::table('users')
    ->select(['id', 'name', 'email'])
    ->where('activo', '=', true)
    ->orderBy('id', 'desc')
    ->limit(10)
    ->get();
```

### Funciones de Construcción de Consultas

- `select(columns: array)`: Especifica las columnas a retornar. Si se omite, por defecto es `*`.
- `where(column: string, operator: string, value: mixed)`: Añade una cláusula `WHERE` básica. El valor se sanitiza automáticamente.
- `orWhere(column: string, operator: string, value: mixed)`: Añade una cláusula `OR WHERE`.
- `whereIn(column: string, values: array)`: Añade una cláusula `WHERE IN`.
- `whereNotIn(column: string, values: array)`: Añade una cláusula `WHERE NOT IN`.
- `whereNull(column: string)`: Añade una cláusula `WHERE column IS NULL`.
- `whereNotNull(column: string)`: Añade una cláusula `WHERE column IS NOT NULL`.
- `join(table: string, first_col: string, operator: string, second_col: string)`: Añade un `INNER JOIN`.
- `leftJoin(...)`, `rightJoin(...)`: Añaden `LEFT JOIN` y `RIGHT JOIN` respectivamente.
- `groupBy(columns: array|string)`: Agrupa los resultados.
- `orderBy(column: string, direction: string = 'asc')`: Ordena los resultados. `direction` puede ser `'asc'` o `'desc'`.
- `limit(count: int)`: Limita el número de resultados.
- `offset(count: int)`: Especifica el punto de inicio para retornar resultados (paginación).

### Funciones de Ejecución

- `get()`: Ejecuta la consulta `SELECT` y devuelve un array de objetos.
- `first()`: Ejecuta la consulta y devuelve el primer objeto resultado, o `null` si no hay resultados.
- `find(id: mixed, pk: string = 'id')`: Busca un registro por su clave primaria. Es un atajo para `where(pk, '=', id)->first()`.
- `count()`: Ejecuta una consulta de conteo y devuelve el número de filas.
- `exists()`: Devuelve `true` si existe al menos un registro que coincida con la consulta, `false` en caso contrario.
- `insert(data: array)`: Inserta un nuevo registro. `data` es un array asociativo `['columna' => 'valor']`.
- `insertGetId(data: array)`: Inserta un registro y devuelve su `id` autoincremental.
- `update(data: array)`: Actualiza los registros que coincidan con las cláusulas `WHERE`. `data` es un array asociativo.
- `delete()`: Elimina los registros que coincidan con las cláusulas `WHERE`.
- `dispense()`: Crea una nueva instancia de `VersaORMModel` vacía para la tabla.

Devuelve arrays de objetos con tipado correcto, listos para usarse en JSON o en lógica PHP.

🧬 VersaORMModel (Estilo RedBeanPHP)
Implementación de un modelo editable y persistente similar a RedBeanPHP, que permite trabajar con registros de base de datos como objetos PHP.

### Funciones de VersaORMModel

- `dispense()`: Crea una nueva instancia vacía del modelo para una tabla específica.
- `load(id: mixed, pk: string = 'id')`: Carga datos de un registro desde la base de datos.
- `store()`: Guarda el modelo en la base de datos (INSERT si es nuevo, UPDATE si existe).
- `trash()`: Elimina el registro del modelo de la base de datos.
- `toArray()`: Convierte el modelo a un array asociativo.
- `__get(key: string)`: Obtiene el valor de un atributo del modelo.
- `__set(key: string, value: mixed)`: Asigna un valor a un atributo del modelo.

**Ejemplo de uso:**
```php
// Crear nuevo modelo
$user = VersaORM::table('users')->dispense();
$user->name = 'Juan Pérez';
$user->email = 'juan@example.com';
$user->store(); // Guarda en DB

// Cargar modelo existente
$loadedUser = VersaORM::table('users')->dispense();
$loadedUser->load(1);
$loadedUser->name = 'Juan Carlos Pérez';
$loadedUser->store(); // Actualiza en DB

// Eliminar modelo
$loadedUser->trash();
```

🧬 Model (ActiveRecord Tradicional)
Gestión de entidades de base de datos estilo ActiveRecord. Cada modelo en PHP se corresponderá con una tabla en la base de datos, permitiendo una interacción orientada a objetos.

### Funciones Estáticas (Operan sobre la tabla)

- `all(): array`: Retorna una colección de todos los registros de la tabla del modelo.
- `find(id: mixed): ?object`: Busca un registro por su clave primaria y devuelve una instancia del modelo, o `null`.
- `findOrFail(id: mixed): object`: Igual que `find`, pero lanza una excepción si no se encuentra el registro.
- `create(data: array): object`: Crea un nuevo registro en la base de datos con los datos proporcionados y devuelve una instancia del modelo.

### Funciones de Instancia (Operan sobre un registro cargado)

- `update(data: array): bool`: Actualiza el registro en la base de datos con los nuevos datos.
- `save(): bool`: Guarda el estado actual del modelo en la base de datos. Realiza una inserción si es un modelo nuevo o una actualización si ya existe.
- `delete(): bool`: Elimina el registro de la base de datos.
- `refresh(): self`: Recarga los datos del modelo desde la base de datos, descartando cualquier cambio no guardado.
- `toArray(): array`: Convierte el modelo y sus atributos a un array asociativo de PHP.
- `toJson(): string`: Convierte el modelo a una cadena JSON.

# Relations

Permite definir relaciones entre modelos.

class User {
public function posts() {
return $this->hasMany('Post', 'user_id', 'id');
}
}

# Tipos soportados:

- hasOne(model, foreign_key, local_key)
- hasMany(...)
- belongsTo(...)
- belongsToMany(...)

Las relaciones pueden cargarse en diferido o eager-loading.

#Schema
Permite inspeccionar la estructura de las tablas.

VersaORM::schema()->getColumns("users");
Funciones:

- getTables()
- getColumns(table)
- getPrimaryKey(table)
- getIndexes(table)
- getForeignKeys(table)

Ideal para validación automática, generación de formularios y caching de esquema.

#Cache
Activa/desactiva y limpia el cache interno de consultas y esquema.

VersaORM::cache()->enable();
VersaORM::cache()->disable();
VersaORM::cache()->clear();
VersaORM::cache()->status();

Puede usarse para mejorar velocidad de introspección y evitar hits innecesarios.

# 🚀 Ejecución de SQL Directo (Raw)

Para casos donde el QueryBuilder no es suficiente, se proporciona una vía para ejecutar SQL crudo de forma segura utilizando consultas preparadas.

- `VersaORM::exec(query: string, bindings: array = []): array`: Ejecuta una consulta SQL cruda y devuelve un array de resultados.
- `VersaORM::transaction(closure: callable): mixed`: Ejecuta una serie de operaciones dentro de una transacción de base de datos. Si la clausura lanza una excepción, la transacción se revierte (rollback). Si se completa, se confirma (commit).

**Ejemplo de uso:**
```php
$users = VersaORM::exec('SELECT * FROM users WHERE activo = ? AND rol = ?', [true, 'editor']);

VersaORM::transaction(function() {
    VersaORM::exec('UPDATE users SET activo = false WHERE id = ?', [10]);
    VersaORM::exec('DELETE FROM logs WHERE user_id = ?', [10]);
});
```

# Utils
Herramientas adicionales útiles para sanitización, conversión y helpers.

- sanitize(input) → limpia valores sospechosos
- castTypes(row) → aplica casting automático
- uuid() → genera UUID
- now() → retorna fecha actual en formato ISO

# Especificación Técnica de la CLI (Fase 1)

Para la implementación inicial, la comunicación entre PHP y Rust se realizará a través de un binario CLI (`versaorm.exe` en Windows, `versaorm` en Linux/macOS). PHP ejecutará este binario y capturará su salida JSON.

### Comando Principal

Se utilizará un único comando principal que recibirá la acción y los datos necesarios en formato JSON a través de un argumento.

**Uso:**
`versaorm <JSON_INPUT>`

- **`<JSON_INPUT>`**: Una cadena JSON que contiene la acción a realizar y sus parámetros.

### Estructura del JSON de Entrada (Input)

El JSON enviado desde PHP al binario Rust tendrá la siguiente estructura:

```json
{
  "config": {
    "driver": "mysql",
    "host": "127.0.0.1",
    "port": 3306,
    "database": "testdb",
    "username": "root",
    "password": "password",
    "charset": "utf8mb4"
  },
  "action": "query", // o "schema", "raw"
  "params": { ... } // Parámetros específicos de la acción
}
```

### Estructura del JSON de Salida (Output)

El binario siempre devolverá un JSON con una estructura predecible para facilitar el manejo de datos y errores en PHP.

**Respuesta Exitosa:**
```json
{
  "status": "success",
  "data": [ ... ], // Array de objetos, un objeto, o un valor primitivo
  "metadata": {
    "execution_time_ms": 15.4,
    "item_count": 10
  }
}
```

**Respuesta con Error:**
```json
{
  "status": "error",
  "error": {
    "code": "DB_CONN_FAILED", // Códigos de error estandarizados
    "message": "No se pudo conectar a la base de datos: ..."
  }
}
```

### Acciones Soportadas

#### 1. Acción `query`

Construye y ejecuta una consulta SELECT.

- **`params` para `query`:**
```json
{
  "table": "users",
  "select": ["id", "name", "email"],
  "joins": [
    {"type": "inner", "table": "posts", "on": "users.id = posts.user_id"}
  ],
  "where": [
    {"column": "activo", "operator": "=", "value": true},
    {"type": "or", "column": "role", "operator": "=", "value": "admin"}
  ],
  "orderBy": [{"column": "id", "direction": "desc"}],
  "limit": 10,
  "offset": 0,
  "method": "get" // get, first, count, exists
}
```

#### 2. Acción `schema`

Inspecciona la base de datos.

- **`params` para `schema`:**
```json
{
  "subject": "tables" // tables, columns, primaryKey, etc.
  "table_name": "users" // Opcional, requerido para `columns` y otros
}
```

### Mapeo de Tipos de Datos (SQL -> Rust -> JSON)

Para garantizar el tipado correcto, se aplicará la siguiente lógica de conversión:

| Tipo SQL (Ejemplos)        | Tipo en Rust (`sqlx`) | Tipo en JSON (`serde_json`) |
| -------------------------- | --------------------- | --------------------------- |
| `INT`, `BIGINT`, `SMALLINT`| `i32`, `i64`          | `Number`                    |
| `FLOAT`, `DOUBLE`, `DECIMAL` | `f64`                 | `Number`                    |
| `BOOLEAN`, `TINYINT(1)`    | `bool`                | `Boolean`                   |
| `VARCHAR`, `TEXT`, `CHAR`  | `String`              | `String`                    |
| `DATE`, `DATETIME`, `TIMESTAMP` | `chrono::NaiveDateTime` | `String` (ISO 8601)       |
| `NULL` (en cualquier columna) | `Option<T>` -> `None`  | `Null`                      |

# Interfaz PHP esperada
VersaORM::connect([...]); // Conectar a DB
VersaORM::table('users'); // QueryBuilder
VersaORM::model('Post'); // Model wrapper
VersaORM::raw('SELECT 1', []); // Query RAW

Devuelve objetos y arrays con datos bien tipados (int, bool, float, null), no solo strings.

# Diseño modular sugerido en Rust

/src
├── connection.rs // Manejo del pool de conexión
├── query.rs // QueryBuilder dinámico
├── model.rs // Modelos y estructuras
├── relation.rs // Carga y lógica de relaciones
├── schema.rs // Introspección de columnas/tablas
├── migration.rs // Migraciones y estado
├── seeder.rs // Seeder
├── utils.rs // Ayudantes comunes
└── ffi.rs // Interfaz con PHP (ext-php-rs o JSON)

# Dependencias de Rust (Sugerencias para `Cargo.toml`)

```toml
[dependencies]
# Para la conexión a bases de datos de forma asíncrona y segura
sqlx = { version = "0.7", features = [ "runtime-tokio-rustls", "mysql", "postgres", "sqlite", "chrono", "decimal" ] }

# Para el runtime asíncrono
tokio = { version = "1", features = ["full"] }

# Para la serialización y deserialización de JSON
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Para construir la interfaz de línea de comandos (CLI)
clap = { version = "4.4", features = ["derive"] }

# Para manejar fechas y tiempos
chrono = "0.4"
```

# Archivos relacionados

- README.md → esta documentación
- Cargo.toml → dependencias de Rust
- php/VersaORM.php → puente PHP
- bin/versaorm → binario CLI (opcional)
- lib/versaorm.so → extensión nativa para PHP
