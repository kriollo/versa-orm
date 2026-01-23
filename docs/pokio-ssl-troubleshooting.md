# Solución: Errores SSL con PostgreSQL y Pokio (async/fork)

## El Problema

Estás recibiendo estos errores:
```
SSL error: decryption failed or bad record mac
SSL SYSCALL error: EOF detected
```

**Causa raíz**: Las conexiones PDO con SSL **no se pueden compartir entre procesos fork**. Cuando usas `async()` de Pokio, se crean procesos hijos que heredan la conexión SSL del proceso padre, causando conflictos.

## Solución Rápida: Desactivar SSL

### Para PostgreSQL Local (Desarrollo)

Agrega `'sslmode' => 'disable'` a tu configuración de base de datos:

```php
<?php

$config = [
    'driver' => 'pgsql',
    'host' => 'localhost',
    'port' => 5432,
    'database' => 'tu_base_datos',
    'username' => 'tu_usuario',
    'password' => 'tu_password',
    'sslmode' => 'disable',  // ← SOLUCIÓN: Desactivar SSL
];

$orm = new VersaORM\VersaORM($config);
```

### Si usas un archivo de configuración

```php
// config/database.php
return [
    'connections' => [
        'pgsql' => [
            'driver' => 'pgsql',
            'host' => env('DB_HOST', 'localhost'),
            'port' => env('DB_PORT', 5432),
            'database' => env('DB_DATABASE'),
            'username' => env('DB_USERNAME'),
            'password' => env('DB_PASSWORD'),
            'sslmode' => env('DB_SSLMODE', 'disable'),  // ← Agregar esto
        ],
    ],
];
```

Y en tu `.env`:
```env
DB_HOST=localhost
DB_PORT=5432
DB_DATABASE=mi_base_datos
DB_USERNAME=mi_usuario
DB_PASSWORD=mi_password
DB_SSLMODE=disable
```

## ¿Por qué funciona desactivar SSL?

- **Sin SSL**: La conexión TCP se puede compartir (con limitaciones) entre procesos
- **Con SSL**: El canal encriptado tiene estado que no se puede compartir entre procesos fork
- **PostgreSQL local**: SSL no es necesario cuando la BD está en localhost

## Solución Avanzada: Reconectar en cada proceso hijo

Si **necesitas SSL** (por ejemplo, en producción con BD remota), reconecta en cada proceso hijo:

```php
use function Pokio\{async, await};

// Guardar la configuración (no la conexión)
$dbConfig = [
    'driver' => 'pgsql',
    'host' => 'db.produccion.com',
    'database' => 'mi_db',
    'username' => 'usuario',
    'password' => getenv('DB_PASSWORD'),
    'sslmode' => 'require',  // SSL activado en producción
];

// En el proceso padre
$orm = new VersaORM($dbConfig);
$orm->schemaCreate('videos', [...]);

// Insertar datos iniciales
$video = VersaModel::dispense('videos');
$video->name = 'Video 1';
$video->store();

// Usar Pokio con reconexión en cada hijo
$promises = [];
for ($i = 1; $i <= 10; $i++) {
    $promises[] = async(function () use ($dbConfig, $i) {
        // ✅ SOLUCIÓN: Crear nueva conexión en el proceso hijo
        $childOrm = new VersaORM($dbConfig);
        VersaModel::setORM($childOrm);
        
        // Ahora puedes usar el ORM normalmente
        $video = VersaModel::load('videos', $i);
        
        // Procesar el video...
        $video->status = 'processed';
        $video->store();
        
        return $video->id;
    });
}

// Esperar todos los resultados
$results = [];
foreach ($promises as $promise) {
    $results[] = await($promise);
}

var_dump($results); // [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
```

## Patrón Recomendado para tu aplicación

Basándome en tu código de `ProcessVideoCommand.php`, deberías hacer esto:

### Antes (con error SSL):
```php
// ProcessVideoCommand.php
public function execute(): void
{
    // ... código ...
    
    $promise = async(function () use ($videoId) {
        // ❌ PROBLEMA: Usa la conexión del proceso padre
        $video = Videos::load('anima_videos', $videoId);
        $video->markAsCompressed();
    });
    
    await($promise);
}
```

### Después (solución 1 - sin SSL):
```php
// En tu configuración de base de datos
$config = [
    'driver' => 'pgsql',
    'host' => 'localhost',
    'database' => 'tu_db',
    'username' => 'usuario',
    'password' => 'password',
    'sslmode' => 'disable',  // ← Agregar esto
];
```

### Después (solución 2 - con SSL + reconexión):
```php
// ProcessVideoCommand.php
private $dbConfig;

public function __construct($dbConfig)
{
    $this->dbConfig = $dbConfig;
}

public function execute(): void
{
    $dbConfig = $this->dbConfig;
    
    $promise = async(function () use ($dbConfig, $videoId) {
        // ✅ SOLUCIÓN: Nueva conexión en el proceso hijo
        $childOrm = new VersaORM($dbConfig);
        VersaModel::setORM($childOrm);
        
        $video = Videos::load('anima_videos', $videoId);
        $video->markAsCompressed();
    });
    
    await($promise);
}
```

## Verificar si SSL está activo

Puedes verificar si tu conexión usa SSL:

```php
$result = $orm->exec("SELECT ssl_is_used() as ssl_enabled");
var_dump($result[0]['ssl_enabled']); // true o false
```

O ver detalles de SSL:

```php
$result = $orm->exec("SELECT * FROM pg_stat_ssl WHERE pid = pg_backend_pid()");
print_r($result[0]);
// Muestra: ssl_version, ssl_cipher, ssl_bits, etc.
```

## Configuración por Entorno

### Desarrollo (localhost)
```php
'sslmode' => 'disable'  // Sin SSL, funciona con Pokio
```

### Staging/Producción (servidor remoto)
```php
'sslmode' => 'require'  // Con SSL, requiere reconexión en procesos hijo
```

## Mejores Prácticas con Pokio

1. **Desarrollo local**: Usa `sslmode=disable` para simplicidad
2. **Producción con Pokio**: Reconecta en cada proceso hijo
3. **Alternativa sin fork**: Usa PHP-FPM con workers múltiples en lugar de fork
4. **Pool de conexiones**: No funciona bien con fork + SSL
5. **Monitoreo**: Logea errores SSL para detectar problemas temprano

## Configuración de PostgreSQL para desarrollo

Si controlas el servidor PostgreSQL, puedes desactivar SSL completamente:

### En `postgresql.conf`:
```conf
ssl = off
```

Luego reinicia PostgreSQL:
```bash
sudo systemctl restart postgresql
```

## Resumen

**Problema**: SSL + Fork (Pokio) = Conflictos de conexión  
**Solución Simple**: `'sslmode' => 'disable'` (desarrollo local)  
**Solución Avanzada**: Reconectar en cada proceso hijo (producción)

Para tu caso específico con PostgreSQL local, simplemente agrega:
```php
'sslmode' => 'disable'
```

Esto resolverá inmediatamente los errores `SSL error: decryption failed or bad record mac` y `SSL SYSCALL error: EOF detected`.
