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

VersaORM se puede utilizar de dos maneras: estáticamente (ideal para aplicaciones simples) o mediante instancias (recomendado para gestionar múltiples conexiones o para inyección de dependencias).

### Conexión a la Base de Datos

**Uso estático:**
```php
use VersaORM\VersaORM;

VersaORM::connect([
    'driver' => 'mysql',
    'host' => 'localhost',
    'database' => 'mi_base_datos',
    'username' => 'usuario',
    'password' => 'contraseña'
]);
```

**Uso con instancias:**
```php
$orm = new VersaORM();
$orm->setConfig([...]);

// Las consultas se realizan sobre la instancia
$users = $orm->table('users')->get();
```

### QueryBuilder

El Query Builder de VersaORM proporciona una interfaz fluida y completa para construir y ejecutar consultas.

#### Selección y Obtención de Resultados
```php
// Obtener todos los usuarios
$users = VersaORM::table('users')->get();

// Obtener columnas específicas y paginar
$users = VersaORM::table('users')
    ->select(['id', 'name', 'email'])
    ->orderBy('id', 'desc')
    ->limit(10)
    ->offset(5)
    ->get();

// Obtener el primer resultado
$user = VersaORM::table('users')->where('id', '=', 1)->first();

// Buscar por clave primaria
$user = VersaORM::table('users')->find(1);
```

#### Cláusulas `WHERE`
```php
// WHERE con operador
$users = VersaORM::table('users')->where('puntos', '>', 100)->get();

// OR WHERE
$users = VersaORM::table('users')
    ->where('puntos', '>', 100)
    ->orWhere('rol', '=', 'admin')
    ->get();

// WHERE IN / WHERE NOT IN
$users = VersaORM::table('users')->whereIn('id', [1, 2, 3])->get();
$admins = VersaORM::table('users')->whereNotIn('rol', ['guest', 'editor'])->get();

// WHERE NULL / WHERE NOT NULL
$users = VersaORM::table('users')->whereNull('fecha_baja')->get();
$activeUsers = VersaORM::table('users')->whereNotNull('ultimo_login')->get();
```

#### Joins
```php
// INNER JOIN
$users = VersaORM::table('users')
    ->join('pedidos', 'users.id', '=', 'pedidos.user_id')
    ->select(['users.name', 'pedidos.total'])
    ->get();

// LEFT JOIN y RIGHT JOIN también están disponibles
$users = VersaORM::table('users')->leftJoin('perfiles', 'users.id', '=', 'perfiles.user_id')->get();
```

#### Agregados y Agrupación
```php
// Contar resultados
$count = VersaORM::table('users')->where('activo', '=', true)->count();

// Verificar si un registro existe
$exists = VersaORM::table('users')->where('email', '=', 'test@example.com')->exists();

// Agrupar resultados
$report = VersaORM::table('pedidos')
    ->select(['estado', 'COUNT(id) as total'])
    ->groupBy('estado')
    ->get();
```

### Operaciones CRUD
```php
// INSERT
$userId = VersaORM::table('users')->insertGetId([
    'name' => 'Juan Pérez',
    'email' => 'juan@example.com'
]);

// UPDATE
VersaORM::table('users')
    ->where('id', '=', $userId)
    ->update(['name' => 'Juan Carlos Pérez']);

// DELETE
VersaORM::table('users')->where('id', '=', $userId)->delete();
```

### Consultas SQL Crudas (Raw)
Para consultas complejas, puedes ejecutar SQL directamente de forma segura.
```php
// SELECT crudo con bindings
$results = VersaORM::exec('SELECT * FROM users WHERE activo = ?', [true]);

// UPDATE/INSERT/DELETE crudo
VersaORM::exec('UPDATE users SET last_login = NOW() WHERE id = ?', [1]);
```
> **Nota**: El método `raw()` es un alias de `exec()` y está marcado como obsoleto. Se recomienda usar `exec()`.

### ORM Models (Estilo ActiveRecord)
VersaORM permite trabajar con registros como objetos dinámicos sin necesidad de definir clases de modelo.

#### Crear un nuevo modelo (dispense)
El método `dispense()` crea un objeto de modelo vacío, listo para ser llenado con datos.
```php
// Crear un nuevo objeto 'user'
$user = VersaORM::table('users')->dispense();

// Asignar propiedades (usa __set)
$user->name = 'Nuevo Usuario';
$user->email = 'nuevo@example.com';

// Guardar en la base de datos (INSERT)
$user->store();

echo "Usuario creado con ID: " . $user->id; // Accede a la propiedad (usa __get)
```

#### Cargar y Actualizar un Modelo
`load()` recupera un registro por su clave primaria.
```php
// Cargar usuario con ID 1
$user = VersaORM::table('users')->dispense();
$user->load(1);

// Modificar y guardar (UPDATE)
$user->name = 'Nombre Actualizado';
$user->store();
```

#### Eliminar un Modelo
```php
// Cargar y eliminar el usuario
$user = VersaORM::table('users')->dispense();
$user->load(1);
$user->trash();
```

### Introspección de Esquema
```php
// Obtener todas las tablas, columnas, índices y claves foráneas
$tables = VersaORM::schema('tables');
$columns = VersaORM::schema('columns', 'users');
$indexes = VersaORM::schema('indexes', 'users');
$foreignKeys = VersaORM::schema('foreignKeys', 'users');
```

### Gestión de Caché
```php
// Habilitar, deshabilitar, limpiar o ver el estado del caché
VersaORM::cache('enable');
VersaORM::cache('clear');
$status = VersaORM::cache('status');
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
