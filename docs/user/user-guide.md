# Guía del Usuario

Este documento provee una guía paso a paso para usuarios que desean utilizar VersaORM en sus proyectos.

## Instalación

### Con Composer

```bash
composer require versaorm/versaorm-php
```

### Manual

Descargar y compilar el binario de Rust:
   1. Navegar al directorio `versaorm_cli`.
   2. Ejecutar `cargo build --release`.

## Uso Básico

```php
use VersaORM\VersaORM;

$orm = new VersaORM();
$orm->setConfig([
    'host' => 'localhost',
    'database' => 'example_db',
    'username' => 'user',
    'password' => 'pass',
    'driver' => 'mysql'
]);

// Ejecutar consulta
$users = $orm->table('users')->where('active', '=', 1)->get();
```

Para más detalles, ver la [documentación técnica](../dev/developer-guide.md).
