# Configuración de VersaORM

## Introducción

Una vez instalado VersaORM, necesitas configurar la conexión a tu base deEsta guía te mostrará cómo configurar VersaORM para trabajar con MySQL, PostgreSQL y SQLite, incluyendo ejemplos prácticos y mejores prácticas.

## Configuración Básica

### Estructura Recomendada

Organiza tu proyecto con esta estructura:

```
mi-proyecto/
├── config/
│   ├── database.php      # Configuración de BD
│   └── app.php          # Configuración general
├── src/
│   ├── models/          # Modelos (opcional)
│   └── controllers/     # Controladores
├── public/
│   └── index.php        # Punto de entrada
├── vendor/              # Dependencias Composer
└── .env                 # Variables de entorno
```

### Configuración con Variables de Entorno

Crea un archivo `.env` en la raíz de tu proyecto:

```env
# Configuración de Base de Datos
DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=mi_aplicacion
DB_USER=mi_usuario
DB_PASS=mi_password

# Configuración de Desarrollo
APP_ENV=development
APP_DEBUG=true

# Configuración de Producción (comentado)
# APP_ENV=production
# APP_DEBUG=false
```

## Configuración para MySQL

### Configuración Básica MySQL

```php
<?php
// config/database.php
require_once 'vendor/autoload.php';

// Cargar variables de entorno (opcional)
if (file_exists(__DIR__ . '/../.env')) {
    $env = parse_ini_file(__DIR__ . '/../.env');
    foreach ($env as $key => $value) {
        $_ENV[$key] = $value;
    }
}

// Configuración MySQL
$config = [
    'host' => $_ENV['DB_HOST'] ?? 'localhost',
    'port' => $_ENV['DB_PORT'] ?? 3306,
    'dbname' => $_ENV['DB_NAME'] ?? 'mi_bd',
    'username' => $_ENV['DB_USER'] ?? 'root',
    'password' => $_ENV['DB_PASS'] ?? '',
    'charset' => 'utf8mb4',
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
    ]
];

// Crear DSN
$dsn = "mysql:host={$config['host']};port={$config['port']};dbname={$config['dbname']};charset={$config['charset']}";

// Inicializar VersaORM
try {
    $orm = new VersaORM($dsn, $config['username'], $config['password'], $config['options']);
    echo "✅ Conexión MySQL exitosa\n";
} catch (PDOException $e) {
    die("❌ Error de conexión MySQL: " . $e->getMessage());
}

return $orm;
?>
```

### Configuración Avanzada MySQL

```php
<?php
// config/mysql-advanced.php
$config = [
    'host' => 'localhost',
    'port' => 3306,
    'dbname' => 'mi_aplicacion',
    'username' => 'app_user',
    'password' => 'secure_password',
    'charset' => 'utf8mb4',
    'options' => [
        // Configuración de errores
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,

        // Modo de fetch por defecto
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,

        // Desactivar emulación de prepared statements
        PDO::ATTR_EMULATE_PREPARES => false,

        // Configuración MySQL específica
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
        PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,

        // Timeout de conexión
        PDO::ATTR_TIMEOUT => 30,

        // Reconexión automática
        PDO::MYSQL_ATTR_RECONNECT => true
    ]
];

$dsn = "mysql:host={$config['host']};port={$config['port']};dbname={$config['dbname']};charset={$config['charset']}";
$orm = new VersaORM($dsn, $config['username'], $config['password'], $config['options']);

// Configurar zona horaria
$orm->exec("SET time_zone = '+00:00'");

return $orm;
?>
```

### Ejemplo de Uso MySQL

```php
<?php
require_once 'config/database.php';

// Crear tabla de ejemplo
$orm->exec("
    CREATE TABLE IF NOT EXISTS usuarios (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        activo BOOLEAN DEFAULT TRUE,
        fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
");

// Insertar usuario de prueba
$usuario = VersaModel::dispense('usuario');
$usuario->nombre = 'Juan Pérez';
$usuario->email = 'juan@ejemplo.com';
$usuario->activo = true;

$id = $$usuario->store();
echo "Usuario creado con ID: $id\n";

// Consultar usuario
$usuario = VersaModel::load('usuario', $id);
echo "Usuario encontrado: {$usuario->nombre} ({$usuario->email})\n";
?>
```

## Configuración para PostgreSQL

### Configuración Básica PostgreSQL

```php
<?php
// config/postgresql.php
$config = [
    'host' => $_ENV['DB_HOST'] ?? 'localhost',
    'port' => $_ENV['DB_PORT'] ?? 5432,
    'dbname' => $_ENV['DB_NAME'] ?? 'mi_bd',
    'username' => $_ENV['DB_USER'] ?? 'postgres',
    'password' => $_ENV['DB_PASS'] ?? '',
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]
];

// DSN para PostgreSQL
$dsn = "pgsql:host={$config['host']};port={$config['port']};dbname={$config['dbname']}";

try {
    $orm = new VersaORM($dsn, $config['username'], $config['password'], $config['options']);

    // Configurar esquema por defecto
    $orm->exec("SET search_path TO public");

    echo "✅ Conexión PostgreSQL exitosa\n";
} catch (PDOException $e) {
    die("❌ Error de conexión PostgreSQL: " . $e->getMessage());
}

return $orm;
?>
```

### Ejemplo de Uso PostgreSQL

```php
<?php
require_once 'config/postgresql.php';

// Crear tabla con tipos específicos de PostgreSQL
$orm->exec("
    CREATE TABLE IF NOT EXISTS productos (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(200) NOT NULL,
        descripcion TEXT,
        precio DECIMAL(10,2) NOT NULL,
        stock INTEGER DEFAULT 0,
        activo BOOLEAN DEFAULT TRUE,
        metadatos JSONB,
        fecha_creacion TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
");

// Insertar producto con datos JSON
$producto = VersaModel::dispense('producto');
$producto->nombre = 'Laptop Gaming';
$producto->descripcion = 'Laptop para gaming de alta gama';
$producto->precio = 1299.99;
$producto->stock = 5;
$producto->metadatos = json_encode([
    'marca' => 'TechBrand',
    'modelo' => 'GX-2024',
    'especificaciones' => [
        'ram' => '16GB',
        'storage' => '1TB SSD',
        'gpu' => 'RTX 4060'
    ]
]);

$id = $$producto->store();
echo "Producto creado con ID: $id\n";

// Consultar con filtro JSON
$productos = $orm->table('productos')
    ->whereRaw("metadatos->>'marca' = ?", ['TechBrand'])
    ->getAll();

foreach ($productos as $prod) {
    echo "Producto: {$prod['nombre']} - Precio: \${$prod['precio']}\n";
}
?>
```

## Configuración para SQLite

### Configuración Básica SQLite

```php
<?php
// config/sqlite.php
$config = [
    'database_path' => __DIR__ . '/../database/app.db',
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]
];

// Crear directorio de base de datos si no existe
$db_dir = dirname($config['database_path']);
if (!is_dir($db_dir)) {
    mkdir($db_dir, 0755, true);
}

// DSN para SQLite
$dsn = "sqlite:{$config['database_path']}";

try {
    $orm = new VersaORM($dsn, null, null, $config['options']);

    // Habilitar claves foráneas en SQLite
    $orm->exec("PRAGMA foreign_keys = ON");

    // Configurar modo WAL para mejor concurrencia
    $orm->exec("PRAGMA journal_mode = WAL");

    echo "✅ Conexión SQLite exitosa\n";
} catch (PDOException $e) {
    die("❌ Error de conexión SQLite: " . $e->getMessage());
}

return $orm;
?>
```

### SQLite en Memoria (Para Testing)

```php
<?php
// config/sqlite-memory.php
$orm = new VersaORM('sqlite::memory:');

// Configurar SQLite en memoria
$orm->exec("PRAGMA foreign_keys = ON");
$orm->exec("PRAGMA synchronous = OFF");
$orm->exec("PRAGMA cache_size = 10000");

return $orm;
?>
```

### Ejemplo de Uso SQLite

```php
<?php
require_once 'config/sqlite.php';

// Crear tablas con relaciones
$orm->exec("
    CREATE TABLE IF NOT EXISTS categorias (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL UNIQUE,
        descripcion TEXT,
        fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
    )
");

$orm->exec("
    CREATE TABLE IF NOT EXISTS articulos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL,
        contenido TEXT,
        categoria_id INTEGER,
        publicado BOOLEAN DEFAULT 0,
        fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (categoria_id) REFERENCES categorias(id)
    )
");

// Insertar categoría
$categoria = VersaModel::dispense('categoria');
$categoria->nombre = 'Tecnología';
$categoria->descripcion = 'Artículos sobre tecnología';
$categoria_id = $$categoria->store();

// Insertar artículo
$articulo = VersaModel::dispense('articulo');
$articulo->titulo = 'Introducción a VersaORM';
$articulo->contenido = 'VersaORM es un ORM simple y potente...';
$articulo->categoria_id = $categoria_id;
$articulo->publicado = true;

$articulo_id = $$articulo->store();
echo "Artículo creado con ID: $articulo_id\n";

// Consultar con JOIN
$articulos = $orm->table('articulos')
    ->join('categorias', 'articulos.categoria_id', '=', 'categorias.id')
    ->select('articulos.titulo', 'categorias.nombre as categoria')
    ->where('articulos.publicado', '=', true)
    ->getAll();

foreach ($articulos as $art) {
    echo "Artículo: {$art['titulo']} - Categoría: {$art['categoria']}\n";
}
?>
```

## Configuración Multi-Base de Datos

### Gestor de Conexiones

```php
<?php
// config/database-manager.php
class DatabaseManager {
    private static $connections = [];

    public static function getConnection($name = 'default') {
        if (!isset(self::$connections[$name])) {
            self::$connections[$name] = self::createConnection($name);
        }
        return self::$connections[$name];
    }

    private static function createConnection($name) {
        $config = self::getConfig($name);

        switch ($config['type']) {
            case 'mysql':
                $dsn = "mysql:host={$config['host']};dbname={$config['dbname']};charset=utf8mb4";
                break;
            case 'pgsql':
                $dsn = "pgsql:host={$config['host']};dbname={$config['dbname']}";
                break;
            case 'sqlite':
                $dsn = "sqlite:{$config['path']}";
                break;
            default:
                throw new Exception("Tipo de base de datos no soportado: {$config['type']}");
        }

        return new VersaORM(
            $dsn,
            $config['username'] ?? null,
            $config['password'] ?? null,
            $config['options'] ?? []
        );
    }

    private static function getConfig($name) {
        $configs = [
            'default' => [
                'type' => 'mysql',
                'host' => 'localhost',
                'dbname' => 'app_principal',
                'username' => 'root',
                'password' => '',
                'options' => [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
            ],
            'analytics' => [
                'type' => 'pgsql',
                'host' => 'analytics-server',
                'dbname' => 'analytics_db',
                'username' => 'analytics_user',
                'password' => 'analytics_pass'
            ],
            'cache' => [
                'type' => 'sqlite',
                'path' => __DIR__ . '/../database/cache.db'
            ]
        ];

        if (!isset($configs[$name])) {
            throw new Exception("Configuración de base de datos no encontrada: $name");
        }

        return $configs[$name];
    }
}

// Uso
$orm_principal = DatabaseManager::getConnection('default');
$orm_analytics = DatabaseManager::getConnection('analytics');
$orm_cache = DatabaseManager::getConnection('cache');
?>
```

## Configuración de Producción

### Configuración Segura

```php
<?php
// config/production.php
class ProductionConfig {
    public static function getORM() {
        // Validar variables de entorno requeridas
        $required_vars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS'];
        foreach ($required_vars as $var) {
            if (empty($_ENV[$var])) {
                throw new Exception("Variable de entorno requerida no encontrada: $var");
            }
        }

        $config = [
            'host' => $_ENV['DB_HOST'],
            'port' => $_ENV['DB_PORT'] ?? 3306,
            'dbname' => $_ENV['DB_NAME'],
            'username' => $_ENV['DB_USER'],
            'password' => $_ENV['DB_PASS'],
            'charset' => 'utf8mb4',
            'options' => [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_PERSISTENT => true,  // Conexiones persistentes
                PDO::ATTR_TIMEOUT => 10,       // Timeout más corto
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4",
                PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true
            ]
        ];

        $dsn = "mysql:host={$config['host']};port={$config['port']};dbname={$config['dbname']};charset={$config['charset']}";

        try {
            $orm = new VersaORM($dsn, $config['username'], $config['password'], $config['options']);

            // Configuraciones adicionales para producción
            $orm->exec("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'");
            $orm->exec("SET SESSION time_zone = '+00:00'");

            return $orm;
        } catch (PDOException $e) {
            // Log del error sin exponer detalles sensibles
            error_log("Error de conexión a base de datos: " . $e->getMessage());
            throw new Exception("Error de conexión a la base de datos");
        }
    }
}
?>
```

## Pruebas de Configuración

### Script de Pruebas Completo

```php
<?php
// tests/test-configuracion.php
require_once 'vendor/autoload.php';

class ConfigurationTest {
    public function testAllDatabases() {
        echo "=== Pruebas de Configuración VersaORM ===\n\n";

        $this->testMySQL();
        $this->testPostgreSQL();
        $this->testSQLite();

        echo "\n=== Pruebas Completadas ===\n";
    }

    private function testMySQL() {
        echo "1. Probando MySQL...\n";
        try {
            $orm = new VersaORM('mysql:host=localhost;dbname=test', 'root', '');
            $result = $orm->getCell("SELECT 'MySQL OK' as test");
            echo "   ✅ MySQL: $result\n";
        } catch (Exception $e) {
            echo "   ❌ MySQL: " . $e->getMessage() . "\n";
        }
    }

    private function testPostgreSQL() {
        echo "2. Probando PostgreSQL...\n";
        try {
            $orm = new VersaORM('pgsql:host=localhost;dbname=test', 'postgres', '');
            $result = $orm->getCell("SELECT 'PostgreSQL OK' as test");
            echo "   ✅ PostgreSQL: $result\n";
        } catch (Exception $e) {
            echo "   ❌ PostgreSQL: " . $e->getMessage() . "\n";
        }
    }

    private function testSQLite() {
        echo "3. Probando SQLite...\n";
        try {
            $orm = new VersaORM('sqlite::memory:');
            $result = $orm->getCell("SELECT 'SQLite OK' as test");
            echo "   ✅ SQLite: $result\n";
        } catch (Exception $e) {
            echo "   ❌ SQLite: " . $e->getMessage() . "\n";
        }
    }
}

$test = new ConfigurationTest();
$test->testAllDatabases();
?>
```

## Solución de Problemas de Configuración

### Error: "Connection refused" (MySQL/PostgreSQL)

**Causa:** Servidor de base de datos no está ejecutándose

**Solución:**
```bash
# MySQL
sudo service mysql start
# O en Windows con XAMPP
# Iniciar MySQL desde el panel de control

# PostgreSQL
sudo service postgresql start
# O en Windows
# Iniciar PostgreSQL desde Services
```

### Error: "Access denied for user"

**Causa:** Credenciales incorrectas

**Solución:**
```php
<?php
// Verificar credenciales paso a paso
$host = 'localhost';
$dbname = 'mi_bd';
$username = 'mi_usuario';
$password = 'mi_password';

// Probar conexión directa con PDO
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    echo "✅ Credenciales correctas";
} catch (PDOException $e) {
    echo "❌ Error: " . $e->getMessage();
}
?>
```

### Error: "Unknown database"

**Causa:** Base de datos no existe

**Solución:**
```sql
-- Crear base de datos manualmente
CREATE DATABASE mi_aplicacion CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- O usar script PHP
<?php
$pdo = new PDO("mysql:host=localhost", "root", "");
$pdo->exec("CREATE DATABASE IF NOT EXISTS mi_aplicacion CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
?>
```

### Error: "SQLSTATE[HY000] [2002] No such file or directory" (SQLite)

**Causa:** Ruta de archivo SQLite incorrecta o sin permisos

**Solución:**
```php
<?php
// Usar ruta absoluta
$db_path = __DIR__ . '/database.db';
$orm = new VersaORM("sqlite:$db_path");

// Verificar permisos del directorio
$db_dir = dirname($db_path);
if (!is_writable($db_dir)) {
    chmod($db_dir, 0755);
}
?>
```

### Error: "SQLSTATE[08006] [7] could not connect to server" (PostgreSQL)

**Causa:** PostgreSQL no está ejecutándose o configuración incorrecta

**Solución:**
```bash
# Verificar estado de PostgreSQL
sudo systemctl status postgresql

# Iniciar PostgreSQL
sudo systemctl start postgresql

# Verificar puerto (por defecto 5432)
netstat -an | grep 5432
```

### Problemas de Rendimiento

**Síntoma:** Consultas lentas

**Solución:**
```php
<?php
// Configurar opciones de rendimiento
$options = [
    PDO::ATTR_PERSISTENT => true,           // Conexiones persistentes
    PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,  // Buffer de consultas
    PDO::ATTR_EMULATE_PREPARES => false,    // Prepared statements nativos
];

$orm = new VersaORM($dsn, $username, $password, $options);
?>
```

### Error: "General error: 2014 Cannot execute queries while other unbuffered queries are active"

**Causa:** Consultas sin buffer en MySQL

**Solución:**
```php
<?php
$options = [
    PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true
];
$orm = new VersaORM($dsn, $username, $password, $options);
?>
```

## Siguiente Paso

Con VersaORM configurado correctamente, es hora de crear tu [primer ejemplo funcional](primer-ejemplo.md) para verificar que todo funciona.

## Resumen

- ✅ **Variables de entorno** para configuración segura
- ✅ **Configuración específica** para MySQL, PostgreSQL y SQLite
- ✅ **Opciones avanzadas** para optimización y seguridad
- ✅ **Multi-base de datos** para aplicaciones complejas
- ✅ **Configuración de producción** con mejores prácticas
- ✅ **Scripts de prueba** para validar configuración
- ✅ **Troubleshooting** para resolver problemas comunes
