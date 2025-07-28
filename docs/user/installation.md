# Instalación con Composer

Esta guía te ayudará a instalar y configurar VersaORM-PHP usando Composer, el gestor de dependencias estándar de PHP.

## Requisitos

- PHP 7.4 o superior
- Composer instalado globalmente
- Extensión JSON de PHP habilitada
- Binario de VersaORM compilado (Rust)

## Instalación

### 1. Instalar via Composer

```bash
composer require versaorm/versaorm-php
```

### 2. Compilar el binario de Rust

VersaORM requiere un binario compilado de Rust para funcionar. Asegúrate de tener Rust instalado y ejecuta:

```bash
cd versaorm_cli
cargo build --release
```

El binario se generará en `versaorm_cli/target/release/versaorm_cli` (o `versaorm_cli.exe` en Windows).

### 3. Verificar la instalación

Después de la instalación, Composer ejecutará automáticamente un script que verifica si el binario existe. Si ves una advertencia, asegúrate de compilar el binario como se indicó en el paso 2.

## Uso básico

### Configuración inicial

```php
<?php

require_once 'vendor/autoload.php';

use VersaORM\VersaORM;

// Configurar la conexión a la base de datos
VersaORM::connect([
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_base_datos',
    'username' => 'usuario',
    'password' => 'contraseña'
]);
```

### QueryBuilder

```php
// Consulta simple
$users = VersaORM::table('users')
    ->select(['id', 'name', 'email'])
    ->where('active', '=', 1)
    ->orderBy('name', 'asc')
    ->get();

// Insertar datos
$userId = VersaORM::table('users')->insertGetId([
    'name' => 'Juan Pérez',
    'email' => 'juan@example.com',
    'active' => 1
]);
```

### Modelo ORM

```php
// Crear nuevo registro
$user = VersaORM::table('users')->dispense();
$user->name = 'María García';
$user->email = 'maria@example.com';
$user->store();

// Cargar registro existente
$user = VersaORM::table('users')->dispense();
$user->load(1); // Cargar usuario con ID 1
$user->name = 'Nuevo nombre';
$user->store(); // Actualizar
```

### Consultas SQL crudas

```php
// Ejecutar consulta personalizada
$result = VersaORM::exec(
    "SELECT * FROM users WHERE created_at > ?",
    ['2023-01-01']
);
```

## Autoload y Namespaces

VersaORM-PHP utiliza el estándar PSR-4 para el autoload. Todas las clases están bajo el namespace `VersaORM`:

- `VersaORM\VersaORM` - Clase principal
- `VersaORM\QueryBuilder` - Constructor de consultas
- `VersaORM\Model` - Modelo ORM

## Configuración avanzada

### Bases de datos soportadas

```php
// MySQL
VersaORM::connect([
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_db',
    'username' => 'usuario',
    'password' => 'contraseña'
]);

// PostgreSQL
VersaORM::connect([
    'driver' => 'postgres',
    'host' => 'localhost',
    'port' => 5432,
    'database' => 'mi_db',
    'username' => 'usuario',
    'password' => 'contraseña'
]);

// SQLite
VersaORM::connect([
    'driver' => 'sqlite',
    'database' => '/ruta/a/database.sqlite'
]);
```

### Ruta del binario personalizada

Si necesitas especificar una ruta personalizada para el binario de VersaORM, puedes configurarla:

```php
// Esto se configuraría internamente en la clase VersaORM
// Por ahora la ruta es fija en la clase
```

## Scripts de desarrollo

El `composer.json` incluye varios scripts útiles:

```bash
# Ejecutar tests
composer test

# Análisis estático de código
composer analyse

# Verificar estilo de código
composer cs-check

# Corregir estilo automáticamente
composer cs-fix
```

## Resolución de problemas

### "VersaORM binary not found"

Este error indica que el binario de Rust no se encuentra. Soluciones:

1. Compilar el binario: `cd versaorm_cli && cargo build --release`
2. Verificar que el archivo existe en `versaorm_cli/target/release/`
3. En Windows, asegúrate de que el archivo tenga extensión `.exe`

### "Failed to execute the VersaORM binary"

Posibles causas:
- El binario no tiene permisos de ejecución (Linux/Mac): `chmod +x versaorm_cli`
- Dependencias de sistema faltantes
- Arquitectura incompatible

### Errores de conexión a la base de datos

- Verificar credenciales de conexión
- Comprobar que el servidor de base de datos esté corriendo
- Verificar que las extensiones PHP necesarias estén instaladas

## Migración desde autoload manual

Si estabas usando el autoload manual (`php/autoload.php`), la migración es simple:

**Antes:**
```php
require_once 'php/autoload.php';
// Usar clases sin namespace
$users = VersaORM::table('users')->get();
```

**Después:**
```php
require_once 'vendor/autoload.php';
use VersaORM\VersaORM;
// Usar con namespace o import
$users = VersaORM::table('users')->get();
```

## Soporte

- **Documentación:** [docs.versaorm.dev](https://docs.versaorm.dev)
- **Issues:** [GitHub Issues](https://github.com/versaorm/versaorm-php/issues)
- **Discusiones:** [GitHub Discussions](https://github.com/versaorm/versaorm-php/discussions)

## Próximos pasos

- Revisa la [documentación completa](../README.md)
- Explora los [ejemplos avanzados](../example_composer.php)
- Consulta la [guía de inicio rápido](./quick-start.md)
