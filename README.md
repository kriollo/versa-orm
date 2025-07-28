# VersaORM-PHP

🚀 **ORM de alto rendimiento para PHP con núcleo en Rust**

[![Status](https://img.shields.io/badge/status-ready-brightgreen.svg)](#)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](#)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4.svg)](#)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#)

## 🌟 Características

- 🔄 **Tipado correcto**: Devuelve `int`, `float`, `bool`, `null`, `string` según corresponda, no todo como string  
- ⚡ **Ultra rápido**: Núcleo en Rust compilado para máximo rendimiento  
- 🧱 **Modular y extensible**: Arquitectura basada en módulos independientes  
- 🔍 **Introspección automática**: Lee estructura de tablas, índices y relaciones  
- 🔗 **QueryBuilder fluido**: API similar a Eloquent/Doctrine  
- 🧠 **Caching inteligente**: Sistema de caché para consultas y esquemas  
- 🔐 **Seguro por diseño**: Consultas preparadas, validación automática  
- 🌐 **Multi-base**: MySQL, PostgreSQL, SQLite  

## 💻 Compatibilidad

- **Sistemas operativos**: Windows, macOS, Linux
- **Lenguaje núcleo**: Rust 2021+
- **Lenguaje interfaz**: PHP 7.4+
- **Bases de datos**: MySQL 5.7+, PostgreSQL 10+, SQLite 3.20+

## 📦 Instalación

### Requisitos previos

- [Rust](https://rustup.rs/) (para compilar el binario)
- PHP 7.4+ con extensiones: `json`, `mbstring`
- Base de datos compatible

### Instalación paso a paso

**1. Instalar mediante Composer (Recomendado)**
```bash
composer require versaorm/versaorm-php
```

### Instalación manual

**1. Clonar el repositorio**
```bash
git clone https://github.com/tu-usuario/versaORM-PHP.git
cd versaORM-PHP
```

**2. Compilar el binario de Rust**
```bash
cd versaorm_cli
cargo build --release
```

**3. Verificar instalación**
```bash
# Windows
.\target\release\versaorm_cli.exe --help

# Linux/macOS  
./target/release/versaorm_cli --help
```

**4. Incluir en tu proyecto PHP**
```php
// Usar el autoloader de Composer
require_once 'vendor/autoload.php';
```

## Uso Básico

### Gestión de conexiones

```php
<?php
// Cargar VersaORM usando Composer
require_once 'vendor/autoload.php';

use VersaORM\VersaORM;

// Configurar la conexión a la base de datos
$orm = new VersaORM();
$orm->setConfig([
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_base_datos',
    'username' => 'usuario',
    'password' => 'contraseña',
    'charset' => 'utf8mb4'
]);

// Cerrar la conexión cuando sea necesario
$orm->disconnect();
```

### QueryBuilder

```php
// Consulta básica
$users = VersaORM::table('users')
    ->select(['id', 'name', 'email'])
    ->where('activo', '=', true)
    ->orderBy('id', 'desc')
    ->limit(10)
    ->get();

// Buscar un registro específico
$user = VersaORM::table('users')->find(1);

// Primer resultado
$firstUser = VersaORM::table('users')
    ->where('email', '=', 'test@example.com')
    ->first();

// Contar registros
$count = VersaORM::table('users')
    ->where('activo', '=', true)
    ->count();

// Verificar existencia
$exists = VersaORM::table('users')
    ->where('email', '=', 'test@example.com')
    ->exists();
```

### Operaciones CRUD

```php
// Insertar
$userId = VersaORM::table('users')->insertGetId([
    'name' => 'Juan Pérez',
    'email' => 'juan@example.com',
    'activo' => true
]);

// Actualizar
VersaORM::table('users')
    ->where('id', '=', $userId)
    ->update(['name' => 'Juan Carlos Pérez']);

// Eliminar
VersaORM::table('users')
    ->where('id', '=', $userId)
    ->delete();
```

### Consultas SQL crudas

```php
// SELECT crudo
$results = VersaORM::exec('SELECT * FROM users WHERE activo = ? LIMIT ?', [true, 10]);

// UPDATE/INSERT/DELETE crudo
VersaORM::exec('UPDATE users SET last_login = NOW() WHERE id = ?', [1]);
```

### Introspección de esquema

```php
// Obtener todas las tablas
$tables = VersaORM::schema('tables');

// Obtener columnas de una tabla
$columns = VersaORM::schema('columns', 'users');

// Obtener clave primaria
$primaryKey = VersaORM::schema('primaryKey', 'users');

// Obtener índices
$indexes = VersaORM::schema('indexes', 'users');

// Obtener claves foráneas
$foreignKeys = VersaORM::schema('foreignKeys', 'users');
```

### Gestión de caché

```php
// Habilitar caché
VersaORM::cache('enable');

// Deshabilitar caché
VersaORM::cache('disable');

// Limpiar caché
VersaORM::cache('clear');

// Estado del caché
$status = VersaORM::cache('status');
```

## ORM Models (Estilo RedBeanPHP)

VersaORM incluye una funcionalidad similar a RedBeanPHP que permite trabajar con modelos como objetos editables y persistentes.

### Crear un nuevo modelo (dispense)

```php
// Crear un nuevo modelo de usuario vacío
$user = VersaORM::table('users')->dispense();

// Asignar propiedades
$user->name = 'Juan Pérez';
$user->email = 'juan@example.com';
$user->active = true;

// Guardar en base de datos
$user->store();

echo "Usuario creado con ID: " . $user->id;
```

### Cargar un modelo existente (load)

```php
// Cargar un usuario por ID
$user = VersaORM::table('users')->dispense();
$user->load(1);

echo "Usuario: " . $user->name . " (" . $user->email . ")";

// También se puede cargar por otra clave
$user->load('juan@example.com', 'email');
```

### Actualizar un modelo (store)

```php
// Cargar usuario existente
$user = VersaORM::table('users')->dispense();
$user->load(1);

// Modificar propiedades
$user->name = 'Juan Carlos Pérez';
$user->last_login = date('Y-m-d H:i:s');

// Guardar cambios
$user->store();
```

### Eliminar un modelo (trash)

```php
// Cargar y eliminar usuario
$user = VersaORM::table('users')->dispense();
$user->load(1);
$user->trash();

echo "Usuario eliminado";
```

### Ejemplo completo de CRUD con Models

```php
<?php
// Usar el autoloader para cargar todas las dependencias
require_once 'php/autoload.php';

// Configurar conexión
VersaORM::connect([
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_base_datos',
    'username' => 'usuario',
    'password' => 'contraseña',
    'charset' => 'utf8mb4'
]);

try {
    // CREATE - Crear nuevo usuario
    $user = VersaORM::table('users')->dispense();
    $user->name = 'Ana García';
    $user->email = 'ana@example.com';
    $user->active = true;
    $user->created_at = date('Y-m-d H:i:s');
    $user->store();
    
    $userId = $user->id;
    echo "Usuario creado con ID: $userId\n";
    
    // READ - Leer usuario
    $loadedUser = VersaORM::table('users')->dispense();
    $loadedUser->load($userId);
    echo "Usuario cargado: {$loadedUser->name} ({$loadedUser->email})\n";
    
    // UPDATE - Actualizar usuario
    $loadedUser->name = 'Ana María García';
    $loadedUser->updated_at = date('Y-m-d H:i:s');
    $loadedUser->store();
    echo "Usuario actualizado\n";
    
    // Verificar cambios
    echo "Datos del usuario: " . json_encode($loadedUser->toArray()) . "\n";
    
    // DELETE - Eliminar usuario
    $loadedUser->trash();
    echo "Usuario eliminado\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

### Métodos disponibles en VersaORMModel

- `load($id, $pk = 'id')`: Carga datos desde la base de datos
- `store()`: Guarda el modelo (INSERT si es nuevo, UPDATE si existe)
- `trash()`: Elimina el registro de la base de datos
- `toArray()`: Convierte el modelo a array asociativo
- `__get($key)`: Obtiene el valor de un atributo
- `__set($key, $value)`: Asigna valor a un atributo

## Métodos del QueryBuilder

### Construcción de consultas

- `select(array $columns)`: Especifica las columnas a retornar
- `where(string $column, string $operator, mixed $value)`: Añade cláusula WHERE
- `orWhere(string $column, string $operator, mixed $value)`: Añade cláusula OR WHERE
- `whereIn(string $column, array $values)`: Añade cláusula WHERE IN
- `whereNotIn(string $column, array $values)`: Añade cláusula WHERE NOT IN
- `whereNull(string $column)`: Añade cláusula WHERE IS NULL
- `whereNotNull(string $column)`: Añade cláusula WHERE IS NOT NULL
- `join(string $table, string $first, string $operator, string $second)`: Añade INNER JOIN
- `leftJoin(...)`: Añade LEFT JOIN
- `rightJoin(...)`: Añade RIGHT JOIN
- `orderBy(string $column, string $direction = 'asc')`: Ordena resultados
- `limit(int $count)`: Limita número de resultados
- `offset(int $count)`: Especifica punto de inicio para paginación

### Ejecución de consultas

- `get()`: Ejecuta SELECT y devuelve array de objetos
- `first()`: Ejecuta SELECT y devuelve primer resultado o null
- `find(mixed $id, string $pk = 'id')`: Busca por clave primaria
- `count()`: Ejecuta COUNT y devuelve número
- `exists()`: Devuelve true si existe al menos un registro
- `insert(array $data)`: Inserta nuevo registro
- `insertGetId(array $data)`: Inserta y devuelve ID autoincremental
- `update(array $data)`: Actualiza registros que coincidan con WHERE
- `delete()`: Elimina registros que coincidan con WHERE
- `dispense()`: Crea un nuevo modelo VersaORMModel vacío para la tabla

## Configuración de Base de Datos

### MySQL

```php
VersaORM::connect([
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_db',
    'username' => 'usuario',
    'password' => 'contraseña',
    'charset' => 'utf8mb4'
]);
```

### PostgreSQL

```php
VersaORM::connect([
    'driver' => 'postgres',
    'host' => 'localhost',
    'port' => 5432,
    'database' => 'mi_db',
    'username' => 'usuario',
    'password' => 'contraseña',
    'charset' => 'utf8'
]);
```

### SQLite

```php
VersaORM::connect([
    'driver' => 'sqlite',
    'database' => '/ruta/a/base_datos.db',
    'username' => '',
    'password' => '',
    'host' => '',
    'port' => 0,
    'charset' => ''
]);
```

## Mapeo de Tipos de Datos

VersaORM mapea automáticamente los tipos de datos SQL a tipos PHP correctos:

| Tipo SQL | Tipo PHP | Descripción |
|----------|----------|-------------|
| `INT`, `BIGINT`, `SMALLINT` | `int` | Números enteros |
| `FLOAT`, `DOUBLE`, `DECIMAL` | `float` | Números decimales |
| `BOOLEAN`, `TINYINT(1)` | `bool` | Valores booleanos |
| `VARCHAR`, `TEXT`, `CHAR` | `string` | Cadenas de texto |
| `DATE`, `DATETIME`, `TIMESTAMP` | `string` | Fechas en formato ISO 8601 |
| `NULL` | `null` | Valores nulos |

## Estructura del Proyecto

```
versaORM-PHP/
├── src/                          # Código fuente PSR-4
│   ├── VersaORM.php              # Clase principal
│   ├── QueryBuilder.php          # QueryBuilder
│   └── Model.php                 # Modelos ORM
├── tests/                        # Pruebas unitarias
│   ├── VersaORMTest.php          # Tests de la clase principal
│   ├── QueryBuilderTest.php      # Tests del QueryBuilder
│   └── ModelTest.php             # Tests del Model
├── docs/                         # Documentación
│   ├── user/                     # Documentación para usuarios
│   │   ├── installation.md       # Guía de instalación
│   │   ├── quick-start.md         # Inicio rápido
│   │   └── user-guide.md          # Guía completa
│   └── dev/                      # Documentación para desarrolladores
│       └── developer-guide.md     # Guía de desarrollo
├── versaorm_cli/                 # Código Rust
│   ├── src/
│   │   ├── main.rs               # Punto de entrada
│   │   ├── connection.rs         # Gestión de conexiones
│   │   ├── query.rs              # Constructor de consultas
│   │   ├── model.rs              # Modelos y relaciones
│   │   ├── schema.rs             # Introspección de esquema
│   │   ├── utils.rs              # Utilidades
│   │   └── cache.rs              # Sistema de caché
│   └── Cargo.toml                # Dependencias de Rust
├── composer.json                 # Configuración de Composer
├── phpunit.xml                   # Configuración de PHPUnit
├── example.php                   # Ejemplo de uso
└── README.md                     # Este archivo
```

## Testing

VersaORM incluye un completo conjunto de pruebas unitarias usando PHPUnit.

### Ejecutar pruebas

```bash
# Instalar dependencias de desarrollo
composer install --dev

# Ejecutar todas las pruebas
composer test

# Ejecutar pruebas con cobertura de código
composer test-coverage

# Análisis estático con PHPStan
composer analyse

# Verificar estilo de código
composer cs-check

# Corregir estilo de código
composer cs-fix
```

### Pruebas incluidas

- **VersaORMTest.php**: Pruebas de la clase principal y configuración
- **QueryBuilderTest.php**: Pruebas del constructor de consultas
- **ModelTest.php**: Pruebas del sistema de modelos ActiveRecord

## Documentación

### Para usuarios finales

- [Guía de instalación](docs/user/installation.md) - Instalación con Composer y manual
- [Inicio rápido](docs/user/quick-start.md) - Primeros pasos con VersaORM
- [Guía completa del usuario](docs/user/user-guide.md) - Documentación completa para usuarios

### Para desarrolladores

- [Guía de desarrollo](docs/dev/developer-guide.md) - Contribuir al proyecto

## Desarrollo y Contribución

### Configurar entorno de desarrollo

```bash
# Clonar el repositorio
git clone https://github.com/versaorm/versaorm-php.git
cd versaorm-php

# Instalar dependencias PHP
composer install

# Compilar binario Rust
cd versaorm_cli
cargo build --release
```

### Compilar en modo desarrollo

```bash
cd versaorm_cli
cargo build
```

### Ejecutar tests de Rust

```bash
cd versaorm_cli
cargo test
```

### Ejemplo de prueba manual

```bash
cd versaorm_cli
echo '{"config":{"driver":"sqlite","database":":memory:","host":"","port":0,"username":"","password":"","charset":""},"action":"query","params":{"table":"users","method":"get"}}' | cargo run
```

## Licencia

Este proyecto está bajo la licencia MIT. Ver archivo LICENSE para más detalles.

## Soporte

Para reportar bugs o solicitar características, por favor crea un issue en el repositorio de GitHub.

## Roadmap

- [ ] Soporte para transacciones
- [ ] Migraciones de base de datos
- [ ] Seeders
- [ ] Relaciones ORM completas
- [ ] Extensión PHP nativa (alternativa al CLI)
- [ ] Pool de conexiones avanzado
- [ ] Métricas y logging
