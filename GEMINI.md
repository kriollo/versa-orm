# 📋 Contexto Completo del Proyecto VersaORM-PHP

## 🎯 SITUACIÓN ACTUAL Y OBJETIVO

Este documento proporciona el contexto completo y actualizado del proyecto VersaORM-PHP para orientar tanto a desarrolladores humanos como a sistemas de IA en el desarrollo continuo del proyecto.

**FECHA DE ÚLTIMA ACTUALIZACIÓN:** 5 de agosto de 2025
**ESTADO DEL PROYECTO:** 85% completo para v1.0 - Funcionalidades core implementadas, falta pulir herramientas de desarrollo

---

## 🏗️ VISIÓN GENERAL Y ARQUITECTURA

VersaORM-PHP es un ORM (Object-Relational Mapper) híbrido de alto rendimiento que combina la familiaridad de PHP con la velocidad extrema de Rust. El proyecto ha demostrado ser exitoso en su arquitectura innovadora y ahora se encuentra en fase de refinamiento para alcanzar la versión 1.0.

### 🎯 **Objetivo Principal**
Crear el ORM más rápido y seguro para PHP, ofreciendo hasta 10x mejor rendimiento que ORMs tradicionales como Eloquent o Doctrine, manteniendo una API familiar y fácil de usar.

### 🏗️ **Arquitectura Híbrida Comprobada**

```
┌─────────────── CAPA PHP ───────────────┐    JSON     ┌─────────────── NÚCLEO RUST ──────────────┐
│                                        │ Payload     │                                         │
│ 🔥 VersaORM.php (Fachada & Config)     │◄───────────►│ 🦀 main.rs (Entry Point - 2570 líneas) │
│ 🔥 QueryBuilder.php (DSL - 1800+ LOC)  │   over      │ 🦀 connection.rs (Pool Management)      │
│ 🔥 VersaModel.php (ActiveRecord - 1200+│   Binary    │ 🦀 query.rs (SQL Builder)              │
│ 🔥 Relations/* (HasOne,HasMany,Belongs) │   IPC       │ 🦀 schema.rs (DB Introspection)        │
│ 🔥 Traits/* (Relationships,Typing)     │             │ 🦀 cache.rs (Advanced Caching)         │
│                                        │             │ 🦀 query_planner.rs (Optimization)     │
└────────────────────────────────────────┘             └─────────────────────────────────────────┘
                         ▲                                               ▲
                         │              🔄 COMUNICACIÓN VALIDADA         │
                         │                                               │
                    ✅ TESTED & STABLE                            ✅ TESTED & STABLE
```

**PUNTOS CLAVE DE LA ARQUITECTURA:**
- ✅ **Comunicación bidireccional probada** via JSON over process execution
- ✅ **Seguridad por diseño** con prepared statements nativos en Rust
- ✅ **Escalabilidad comprobada** con connection pooling asíncrono
- ✅ **Tipado fuerte** bidireccional PHP ↔ Rust ↔ Database

**INFORMACIÓN DEL PROYECTO:**
- **Nombre**: `versaorm/versaorm-php`
- **Licencia**: MIT
- **PHP**: 7.4+ | 8.0+ (Tested hasta 8.3)
- **Bases de Datos**: MySQL 5.7+, PostgreSQL 10+, SQLite 3.6+
- **Estado**: 85% completo para v1.0 - Core estable, herramientas en desarrollo
-   **Fácil Integración:** Diseñado para integrarse sin problemas en proyectos PHP existentes.

**Información del `composer.json`:**
-   **Nombre:** `versaorm/versaorm-php`
-   **Descripción:** ORM de alto rendimiento para PHP con núcleo en Rust - Tipado correcto, ultra rápido, seguro por diseño.
-   **Tipo:** `library`
-   **Palabras Clave:** `orm`, `database`, `mysql`, `postgresql`, `sqlite`, `rust`, `performance`, `query-builder`, `redbean`, `eloquent`
-   **Licencia:** MIT
-   **Requisitos PHP:** `^7.4|^8.0`
-   **Extensiones PHP:** `ext-json` (obligatorio), `ext-mbstring` (sugerido)
-   **Dependencias de Desarrollo:** `phpunit/phpunit: ^10.0`, `phpstan/phpstan: ^1.10`, `squizlabs/php_codesniffer: ^3.7`
-   **Autoloading:** `PSR-4` para `VersaORM\` en `src/` y `VersaORM\Tests\` en `tests/`.
-   **Scripts:** `test` (phpunit), `test-coverage`, `analyse` (phpstan), `cs-check` (phpcs), `cs-fix` (phpcbf).

## 2. Arquitectura del Proyecto

VersaORM-PHP emplea una arquitectura híbrida única que combina una interfaz de alto nivel en PHP con un núcleo de ejecución de bajo nivel en Rust.

```
┌───────────────────────────┐      ┌──────────────────────────────────┐
│        Capa de PHP        │      │           Núcleo de Rust         │
│  (Interfaz de Usuario)    │      │      (Motor de Base de Datos)    │
├───────────────────────────┤      ├──────────────────────────────────┤
│                           │      │                                  │
│  - VersaORM.php (Fachada) │      │  - main.rs (Punto de entrada)    │
│  - QueryBuilder.php       │      │  - connection.rs (Gestor de Conex) │
│  - VersaModel.php         │      │  - query.rs (Constructor SQL)    │
│  - Traits/Modelos         │      │  - schema.rs (Inspector)         │
│                           │      │                                  │
└─────────────┬─────────────┘      └─────────────────▲────────────────┘
              │                                      │
              │           Comunicación vía           │
              │         Línea de Comandos (CLI)      │
              │                                      │
              ▼                                      │
┌───────────────────────────┐      ┌─────────────────┴────────────────┐
│      Payload JSON         │      │         Respuesta JSON           │
│ (Config + Acción + Params)│◄─────►│      (Datos o Error Detallado)   │
└───────────────────────────┘      └──────────────────────────────────┘
```

### 2.1. La Capa de PHP (`src/`)

Esta capa es la interfaz principal para los desarrolladores PHP. Sus responsabilidades incluyen:
-   Proveer una API fluida y expresiva (`QueryBuilder`, `VersaModel`).
-   Construir el payload de la consulta: Traduce las llamadas a métodos encadenados en una estructura de datos PHP (array).
-   Gestionar la comunicación con el núcleo de Rust: `VersaORM.php` serializa el array de consulta a JSON y ejecuta el binario de Rust.
-   Procesar la respuesta: Deserializa el JSON de Rust y lo transforma en el formato de salida adecuado (arrays de datos u objetos `VersaModel`).
-   Manejar errores: Captura los errores de Rust y los lanza como `VersaORMException` con contexto PHP.

**La capa de PHP se comunica con el núcleo de Rust a través de JSON, no directamente con la base de datos.**

### 2.2. El Núcleo de Rust (`versaorm_cli/`)

Este es el motor de alto rendimiento del ORM, implementado como un binario de línea de comandos independiente. Sus responsabilidades son:
-   Recibir y parsear el payload JSON de PHP.
-   Gestionar la conexión a la base de datos: Utiliza `sqlx` para un pool de conexiones asíncrono y seguro (MySQL, PostgreSQL, SQLite).
-   Construir y ejecutar SQL seguro: Genera consultas SQL utilizando **consultas preparadas** para prevenir inyecciones SQL.
-   Mapear tipos de datos: Asegura la preservación de tipos de datos entre la base de datos y JSON.
-   Inspeccionar el esquema: Realiza consultas a los metadatos de la base de datos.
-   Devolver una respuesta JSON estandarizada: Siempre devuelve JSON, ya sea con datos (`status: "success"`) o errores (`status: "error"`).

**El núcleo de Rust es el único componente que interactúa directamente con la base de datos.**

### 2.3. Flujo de una Consulta

1.  **Código PHP:** El desarrollador invoca métodos del ORM (ej. `$orm->table('users')->where('status', '=', 'active')->findAll();`).
2.  **Capa PHP:** El `QueryBuilder` construye un array de consulta. `VersaORM.php` crea un payload JSON y ejecuta el binario `versaorm_cli`.
3.  **Núcleo Rust:** Parsea el JSON, se conecta a la DB, construye el SQL (`SELECT * FROM users WHERE status = ?`), ejecuta la consulta con parámetros vinculados, serializa los resultados a JSON y los imprime a `stdout`.
4.  **Capa PHP:** `VersaORM.php` lee el JSON de `stdout`, lo deserializa y lo convierte en objetos `VersaModel` para el usuario.

## 3. Instalación

### 3.1. Requisitos del Sistema

-   PHP 7.4 o superior
-   Extensiones PHP: `json`, `mbstring` (recomendada)
-   Acceso a la línea de comandos (Composer, Git)
-   Base de datos: MySQL 5.7+, MariaDB 10.2+, PostgreSQL 10+, o SQLite 3.6+
-   Rust 1.70.0 o superior (para desarrollo/compilación del núcleo)
-   Cargo (incluido con Rust)
-   Compiladores C/C++ (gcc, clang, o MSVC)

### 3.2. Instalación con Composer (Recomendado)

```bash
composer require versaorm/versaorm-php
```
Incluye el autoloader de Composer en tu proyecto:
```php
require_once 'vendor/autoload.php';
```

### 3.3. Instalación Manual

1.  **Clonar el repositorio:**
    ```bash
git clone https://github.com/kriollo/versa-orm.git
```
2.  **Incluir archivos PHP:**
    ```php
require_once 'path/to/versa-orm/src/VersaORM.php';
require_once 'path/to/versa-orm/src/VersaModel.php';
require_once 'path/to/versa-orm/src/QueryBuilder.php';
require_once 'path/to/versa-orm/src/Traits/VersaORMTrait.php';
```
3.  **Verificar el binario de Rust:** Los binarios precompilados se encuentran en `src/binary/`. Asegúrate de que el binario correspondiente a tu OS tenga permisos de ejecución (ej. `chmod +x src/binary/versaorm_cli_linux`).

## 4. Configuración

Para configurar la conexión a la base de datos, se pasa un array de configuración al constructor de `VersaORM\VersaORM`.

```php
use VersaORM\VersaORM;
use VersaORM\VersaModel;

$config = [
    'driver'   => 'mysql',
    'host'     => 'localhost',
    'port'     => 3306,
    'database' => 'mi_base_de_datos',
    'username' => 'mi_usuario',
    'password' => 'mi_contraseña',
    'charset'  => 'utf8mb4',
    'debug'    => true, // Opcional: actívalo para obtener errores detallados
];

$orm = new VersaORM($config);

// Configuración global para modelos (recomendado)
VersaModel::setORM($orm);
```

**Parámetros de Configuración:**
-   `driver` (obligatorio): `mysql`, `pgsql`, `sqlite`.
-   `host` (obligatorio): Dirección del servidor de la base de datos.
-   `port` (opcional): Puerto de la base de datos (por defecto: 3306 para MySQL, 5432 para PostgreSQL).
-   `database` (obligatorio): Nombre de la base de datos.
-   `username` (obligatorio): Nombre de usuario.
-   `password` (obligatorio): Contraseña.
-   `charset` (opcional): Juego de caracteres (ej. `utf8mb4`).
-   `debug` (opcional): `true` para mensajes de error detallados (desactivar en producción).

## 5. Uso Básico (Operaciones CRUD)

VersaORM facilita las operaciones CRUD a través de `VersaModel`, que implementa el patrón Active Record.

### 5.1. Crear Registros (`dispense()`, `store()`)

```php
use VersaORM\VersaModel;

$user = VersaModel::dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan.perez@example.com';
$user->store(); // Ejecuta INSERT
echo "Usuario creado con ID: " . $user->id;
```

### 5.2. Leer Registros (`load()`, `findAll()`)

```php
// Cargar por ID
$user = VersaModel::load('users', 1);
if ($user) { echo $user->name; }

// Cargar múltiples
$allUsers = VersaModel::findAll('users');
foreach ($allUsers as $user) { echo $user->name . "\n"; }
```

### 5.3. Actualizar Registros (`store()`)

```php
$user = VersaModel::load('users', 1);
if ($user) {
    $user->email = 'nuevo@example.com';
    $user->store(); // Ejecuta UPDATE
}
```

### 5.4. Eliminar Registros (`trash()`)

```php
$user = VersaModel::load('users', 1);
if ($user) {
    $user->trash(); // Ejecuta DELETE
}
```

### 5.5. Exportar a Array (`export()`, `exportAll()`)

```php
$user = VersaModel::load('users', 1);
$userData = $user->export(); // Convierte el modelo a array

$users = VersaModel::findAll('users');
$usersData = VersaModel::exportAll($users); // Convierte una colección de modelos a array de arrays
```

## 6. Guía del Query Builder

El Query Builder permite construir consultas SQL complejas de forma programática y segura. Se inicia con `$orm->table('nombre_tabla')`.

### 6.1. Obtención de Resultados

-   **Arrays (para APIs/JSON):** `getAll()`, `firstArray()`.
-   **Objetos (para lógica de negocio):** `findAll()`, `findOne()`.

### 6.2. Métodos de Construcción

-   `select(array $columns)`: Especifica columnas.
-   `where(string $column, string $operator, mixed $value)`: Añade cláusulas WHERE.
-   `orWhere(...)`: Cláusulas OR.
-   `whereIn(string $column, array $values)`, `whereNotIn(...)`, `whereNull(...)`, `whereNotNull(...)`, `whereBetween(...)`.
-   `whereRaw(string $sql, array $bindings = [])`: SQL crudo (usar con precaución).
-   `join(string $table, string $firstCol, string $operator, string $secondCol)`: `INNER JOIN`.
-   `leftJoin(...)`, `rightJoin(...)`.
-   `orderBy(string $column, string $direction = 'asc')`: Ordena resultados.
-   `groupBy(string|array $columns)`: Agrupa resultados.
-   `limit(int $count)`, `offset(int $count)`: Paginación.

### 6.3. Funciones de Agregado

-   `count()`: Número de registros.
-   `exists()`: Verifica si existen registros.

### 6.4. Operaciones de Escritura (con Query Builder)

-   `insert(array $data)`: Inserta un nuevo registro.
-   `insertGetId(array $data)`: Inserta y devuelve el ID.
-   `update(array $data)`: Actualiza registros que coinciden con WHERE.
-   `delete()`: Elimina registros que coinciden con WHERE.

## 7. Guía de Modelos y Objetos

La creación de modelos personalizados (`class User extends BaseModel`) permite encapsular lógica de negocio, definir "scopes" de consulta y gestionar validación/relaciones.

### 7.1. Creación de Modelos Personalizados

Los modelos extienden `Example\Models\BaseModel` o usan el `VersaORM\Traits\VersaORMTrait`.

```php
// en models/User.php
namespace App\Models;

use Example\Models\BaseModel;

class User extends BaseModel
{
    protected string $table = 'users';
    protected array $fillable = ['name', 'email', 'password', 'status'];

    public function isActive(): bool { return $this->status === 'active'; }
    public static function findActive(): array { /* ... */ }
}
```

### 7.2. `VersaORMTrait`

Proporciona `$this->db` (instancia de `VersaORM`), `connectORM()`, `disconnectORM()` y `getORM()`.

### 7.3. Arrays vs. Objetos

-   **Arrays (`getAll`, `firstArray`, `exec`):** Para velocidad, bajo consumo de memoria, APIs JSON, reportes, agregados.
-   **Objetos (`findAll`, `findOne`, modelos personalizados):** Para lógica de negocio, manipulación de entidades, código expresivo y mantenible.

## 8. Guía de la Herramienta de Línea de Comandos (CLI)

El binario `versaorm_cli` (núcleo de Rust) puede usarse directamente para depuración o scripting. Se encuentra en `src/binary/`.

**Uso:**
```bash
# Linux/macOS
./src/binary/versaorm_cli_linux '<json_payload>'

# Windows
.\src\binary\versaorm_cli_windows.exe "<json_payload>"
```
El `<json_payload>` es una cadena JSON con `config`, `action` (`query`, `raw`, `schema`, `cache`) y `params`. La salida es JSON a `stdout`.

**Ejemplo de Payload JSON:**
```json
{
  "config": { /* ... */ },
  "action": "query",
  "params": {
    "table": "tasks",
    "method": "get",
    "where": [
      { "column": "completed", "operator": "=", "value": true }
    ]
  }
}
```

## 9. Directrices de Desarrollo y Contribución

### 9.1. Estándares de Código PHP

-   Sigue **PSR-12 (Extended Coding Style)**.
-   **Verificación:** `vendor/bin/phpcs src/`
-   **Corrección Automática:** `vendor/bin/phpcbf src/`
-   **Análisis Estático:** `vendor/bin/phpstan analyse src --level=8`

### 9.2. Estándares de Código Rust

-   Sigue los estándares de formato oficiales de Rust.
-   **Formato:** `cd versaorm_cli && cargo fmt`
-   **Linting:** `cd versaorm_cli && cargo clippy`

### 9.3. Mensajes de Commit

Sigue la especificación de **Conventional Commits**: `<tipo>[ámbito opcional]: <descripción>`.
-   **Tipos:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`.
-   **Ejemplos:**
    -   `feat(query-builder): añadir soporte para whereBetween`
    -   `fix(rust-core): corregir el parseo de tipos decimales en postgres`

### 9.4. Proceso de Pull Request (PR)

1.  Fork el repositorio.
2.  Crea una nueva rama (`git checkout -b feature/mi-nueva-caracteristica`).
3.  Realiza tus cambios, siguiendo los estándares.
4.  Asegúrate de que las pruebas pasan (`vendor/bin/phpunit` y `cargo test`).
5.  Haz commit con mensajes convencionales.
6.  Envía tus cambios a tu fork (`git push origin feature/mi-nueva-caracteristica`).
7.  Abre un Pull Request en GitHub, explicando el **qué** y el **cómo**.

## 10. Estructura del Proyecto

```
versaORM-PHP/
├── .github/              # Configuraciones de GitHub (ej. Workflows de CI/CD)
├── docs/                 # Documentación del proyecto (guías de usuario y contribuidor)
│   ├── contributor-guide/
│   ├── getting-started/
│   └── user-guide/
├── example/              # Aplicación de ejemplo (To-Do App)
├── logs/                 # Directorio para logs generados por el ORM
├── src/                  # Código fuente de la capa PHP de VersaORM
│   ├── binary/           # Binarios de Rust precompilados por OS
│   ├── Traits/           # Traits PHP (ej. VersaORMTrait.php)
│   ├── QueryBuilder.php  # Constructor de consultas PHP
│   ├── VersaModel.php    # Clase base para modelos Active Record
│   ├── VersaORM.php      # Clase principal del ORM (interfaz con Rust)
│   └── VersaORMException.php # Excepción personalizada del ORM
├── tests/                # Pruebas unitarias y de integración para PHPUnit
│   ├── QueryBuilderTest.php
│   ├── VersaModelTest.php
│   └── VersaORMTest.php
├── versaorm_cli/         # Código fuente del núcleo Rust
│   ├── src/              # Archivos fuente de Rust
│   │   ├── cache.rs      # Módulo de caché
│   │   ├── connection.rs # Gestión de conexiones a DB
│   │   ├── main.rs       # Punto de entrada del binario Rust
│   │   ├── model.rs      # Lógica de modelos en Rust
│   │   ├── query.rs      # Construcción de consultas SQL en Rust
│   │   ├── schema.rs     # Inspección de esquema de DB
│   │   └── utils.rs      # Utilidades varias (sanitización, casting)
│   └── Cargo.toml        # Configuración de dependencias y build de Rust
├── composer.json         # Configuración de Composer para el proyecto PHP
├── phpunit.xml           # Configuración de PHPUnit
└── README.md             # README principal del proyecto
```

## 11. Modo Freeze - Protección de Esquema

El **Modo Freeze** es una característica de seguridad avanzada que protege el esquema de la base de datos contra modificaciones accidentales o no autorizadas. Cuando está activo, bloquea todas las operaciones DDL (Data Definition Language).

### 11.1. Tipos de Freeze

**Freeze Global:**
- Bloquea todas las operaciones DDL en toda la aplicación
- Se activa con `$orm->freeze(true)`
- Estado verificable con `$orm->isFrozen()`

**Freeze por Modelo:**
- Protege modelos específicos sin afectar otros
- Se configura con `$orm->freezeModel(ModelClass::class, true)`
- Verificable con `$orm->isModelFrozen(ModelClass::class)`

### 11.2. Operaciones Bloqueadas

Cuando el freeze está activo, las siguientes operaciones DDL son bloqueadas:
- `CREATE TABLE`, `DROP TABLE`, `ALTER TABLE`, `TRUNCATE TABLE`
- `ADD COLUMN`, `DROP COLUMN`, `MODIFY COLUMN`, `RENAME COLUMN`
- `CREATE INDEX`, `DROP INDEX`, `ADD/DROP FOREIGN KEY`
- Consultas SQL raw que contengan comandos DDL

### 11.3. Implementación Bicapa

**Lado PHP (`VersaORM.php`):**
- Gestiona estado freeze (`$isFrozen`, `$frozenModels`)
- Métodos de control: `freeze()`, `freezeModel()`, `isFrozen()`, `isModelFrozen()`
- Logging de seguridad y auditoría de violaciones
- Validación previa con `validateFreezeOperation()`

**Lado Rust (`main.rs`):**
- Recibe estado freeze en cada payload JSON
- Validación de bajo nivel con `validate_freeze_operation()`
- Detección de DDL en consultas raw con `validate_raw_query_freeze()`
- Bloqueo efectivo antes de ejecución en base de datos

### 11.4. Manejo de Errores

Las violaciones de freeze lanzan `VersaORMException` con:
- Código de error: `FREEZE_VIOLATION`
- Mensaje descriptivo del bloqueo
- Contexto detallado en modo debug
- Sugerencias para resolver el problema

### 11.5. Logging y Auditoría

El sistema registra automáticamente:
- Activación/desactivación de freeze (`FREEZE_MODE_ACTIVATED/DEACTIVATED`)
- Freeze por modelo (`MODEL_FROZEN/UNFROZEN`)
- Intentos de violación (`FREEZE_VIOLATION_ATTEMPT`)
- Logs guardados en `logs/security-YYYY-MM-DD.log`

## 12. Resumen del Código PHP (`src/`)

-   **`VersaORM.php`**: La clase principal que actúa como fachada. Gestiona la configuración de la base de datos, la comunicación con el binario de Rust (serializando/deserializando JSON y ejecutando comandos), y proporciona métodos para iniciar el Query Builder (`table()`) y ejecutar SQL crudo (`exec()`). También maneja la lógica de errores y logging.
-   **`QueryBuilder.php`**: Permite construir consultas SQL de forma programática. Ofrece métodos encadenables para `SELECT`, `WHERE`, `JOIN`, `ORDER BY`, `LIMIT`, `OFFSET`, así como operaciones `INSERT`, `UPDATE` y `DELETE`. Traduce estas operaciones a un formato que el núcleo de Rust puede entender.
-   **`VersaModel.php`**: Implementa el patrón Active Record. Representa una fila de la base de datos como un objeto PHP. Proporciona métodos para `dispense` (crear nuevo), `load` (cargar por ID), `store` (guardar/actualizar) y `trash` (eliminar). También incluye métodos estáticos para operaciones comunes y para configurar la instancia global del ORM.
-   **`VersaORMException.php`**: Una clase de excepción personalizada que extiende `Exception`, diseñada para encapsular errores específicos de VersaORM, incluyendo detalles como el código de error, la consulta SQL que falló y los parámetros asociados.
-   **`Traits/VersaORMTrait.php`**: Un trait que proporciona funcionalidades comunes relacionadas con la conexión y desconexión del ORM, útil para modelos personalizados que necesitan acceder a la instancia de `VersaORM`.

## 13. Resumen del Código Rust (`versaorm_cli/src/`))

-   **`main.rs`**: El punto de entrada del binario de Rust. Parsea los argumentos de la línea de comandos (el payload JSON), gestiona la conexión a la base de datos a través de `ConnectionManager`, y delega la ejecución de las acciones (`query`, `raw`, `schema`, `cache`) a los módulos correspondientes. También maneja la salida JSON y el logging.
-   **`connection.rs`**: Gestiona las conexiones a la base de datos. Define `DatabaseConfig` y `ConnectionManager` para establecer y mantener pools de conexiones (`sqlx`) para MySQL, PostgreSQL y SQLite. Contiene la lógica para ejecutar consultas raw y para el binding de parámetros.
-   **`query.rs`**: Implementa el Query Builder en el lado de Rust. Recibe los parámetros de consulta de PHP y construye la sentencia SQL final, incluyendo `SELECT`, `WHERE`, `JOIN`, `ORDER BY`, `LIMIT`, `OFFSET`. Es responsable de generar SQL seguro y parametrizado. También maneja la construcción de sentencias `INSERT`, `UPDATE` y `DELETE`.
-   **`model.rs`**: Define la estructura `Model` en Rust, que representa una entidad de la base de datos. Incluye métodos para cargar y guardar datos, y para convertir el modelo a JSON. Aunque la lógica principal de Active Record está en PHP, este módulo podría usarse para operaciones más cercanas a la base de datos si fuera necesario.
-   **`schema.rs`**: Proporciona funcionalidades para inspeccionar el esquema de la base de datos. Permite obtener información sobre tablas, columnas, claves primarias, índices y claves foráneas para diferentes tipos de bases de datos.
-   **`utils.rs`**: Contiene funciones de utilidad generales, como sanitización de cadenas, casting de tipos de datos, generación de UUIDs y manejo de fechas. También incluye funciones para validar y limpiar nombres de tablas y columnas, y para construir cláusulas WHERE de forma segura.
-   **`cache.rs`**: Implementa un sistema de caché simple para consultas y esquemas, utilizando `HashMap`s protegidos por `Mutex` y `Arc` para concurrencia segura. Permite habilitar, deshabilitar, limpiar y verificar el estado de la caché.

## 14. Pruebas y Validación de Calidad

El proyecto utiliza **PHPUnit** para las pruebas unitarias y de integración de PHP, y el sistema de pruebas de Rust (`cargo test`) para el núcleo. Además, se exige validación estática y de estilo en ambos lenguajes.

-   **Análisis Estático PHP:** `vendor/bin/phpstan analyse src --level=9`
-   **Lint y Formato PHP:** `vendor/bin/phpcs src/` y `vendor/bin/phpcbf src/`
-   **Pruebas PHP:** `vendor/bin/phpunit`
-   **Análisis Estático Rust:** `cd versaorm_cli && cargo clippy`
-   **Formato Rust:** `cd versaorm_cli && cargo fmt`
-   **Pruebas Rust:** `cd versaorm_cli && cargo test`
-   **Compilación del núcleo Rust:** `cd versaorm_cli && cargo build --release` (el binario resultante debe copiarse a `src/binary/` y reemplazar el anterior)

**Checklist de calidad para cada entrega o tarea:**
1. Ejecutar `phpstan` y corregir todos los errores PHP sin perder funcionalidad.
2. Ejecutar `cargo clippy` y corregir todos los errores Rust sin perder funcionalidad.
3. Compilar el binario Rust y copiarlo a `src/binary`.
4. Ejecutar los tests de PHP y Rust, corregir errores y volver a validar todo el flujo.

Los archivos de prueba PHP se encuentran en la carpeta `tests/`.

## 15. Integración Continua / Despliegue Continuo (CI/CD)

El proyecto utiliza **GitHub Actions** para la integración continua. Los flujos de trabajo automatizados incluyen:
- Validación de código PHP (`phpstan`, `phpcs`, `phpunit`).
- Validación de código Rust (`cargo clippy`, `cargo test`).
- Compilación y despliegue del binario Rust en la carpeta `src/binary`.
- Ejecución de pruebas completas tras cada cambio en el repositorio.
- los logs se guardan en la carpeta `logs/` que está en la raiz del proyecto, para su revisión posterior.

Esto garantiza que cada commit y Pull Request pase por un pipeline de calidad y pruebas antes de ser aceptado.

## 16. Como debes actuar
-   **Revisar el código existente:** Familiarízate con la estructura y convenciones del proyecto.
-   **Seguir las guías de estilo:** Asegúrate de que tu código
    cumple con los estándares de codificación establecidos.
-   **Escribir pruebas:** Cada nueva funcionalidad debe incluir pruebas unitarias e integración.
-   **Documentar cambios:** Actualiza la documentación del proyecto según sea necesario.
-   **responder en español:** Utiliza el español para la comunicación y documentación del proyecto, manteniendo la coherencia con el idioma del código y los comentarios.
-  **personalidad** eres un experto en PHP y Rust, con un enfoque en la seguridad, rendimiento y buenas prácticas de desarrollo. Tu objetivo es crear un ORM que sea fácil de usar, rápido y seguro, aprovechando las fortalezas de ambos lenguajes.
