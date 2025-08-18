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
DB_DRIVER=mysql
DB_HOST=localhost
DB_PORT=3306
DB_DATABASE=mi_aplicacion
DB_USERNAME=mi_usuario
DB_PASSWORD=mi_password

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
    'driver'   => $_ENV['DB_DRIVER'] ?? 'mysql',
    'host'     => $_ENV['DB_HOST'] ?? 'localhost',
    'port'     => $_ENV['DB_PORT'] ?? 3306,
    'database' => $_ENV['DB_DATABASE'] ?? 'mi_bd',
    'username' => $_ENV['DB_USERNAME'] ?? 'root',
    'password' => $_ENV['DB_PASSWORD'] ?? '',
    'charset'  => 'utf8mb4',
    'options'  => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
    ]
];

// Inicializar VersaORM
try {
    $orm = new VersaORM($config);
    VersaModel::setORM($orm);
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
    'driver'   => 'mysql',
    'host'     => 'localhost',
    'port'     => 3306,
    'database' => 'mi_aplicacion',
    'username' => 'app_user',
    'password' => 'secure_password',
    'charset'  => 'utf8mb4',
    'options'  => [
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
    ]
];

$orm = new VersaORM($config);
VersaModel::setORM($orm);

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
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// Insertar usuario de prueba
$user = VersaModel::dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan@ejemplo.com';
$user->active = true;

$id = $user->store();
echo "Usuario creado con ID: $id\n";

// Consultar usuario
$user = VersaModel::load('users', $id);
echo "Usuario encontrado: {$user->name} ({$user->email})\n";
?>
```

## Configuración para PostgreSQL

### Configuración Básica PostgreSQL

```php
<?php
// config/postgresql.php
$config = [
    // Se recomienda usar 'postgresql' (alias: pgsql, postgres)
    'driver'   => 'postgresql',
    'host'     => $_ENV['DB_HOST'] ?? 'localhost',
    'port'     => $_ENV['DB_PORT'] ?? 5432,
    'database' => $_ENV['DB_DATABASE'] ?? 'mi_bd',
    'username' => $_ENV['DB_USERNAME'] ?? 'postgres',
    'password' => $_ENV['DB_PASSWORD'] ?? '',
    'options'  => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]
];

try {
    $orm = new VersaORM($config);
    VersaModel::setORM($orm);

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
    CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        stock INTEGER DEFAULT 0,
        active BOOLEAN DEFAULT TRUE,
        metadata JSONB,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    )
");

// Insertar producto con datos JSON
$product = VersaModel::dispense('products');
$product->name = 'Laptop Gaming';
$product->description = 'Laptop para gaming de alta gama';
$product->price = 1299.99;
$product->stock = 5;
$product->metadata = json_encode([
    'brand' => 'TechBrand',
    'model' => 'GX-2024',
    'specs' => [
        'ram' => '16GB',
        'storage' => '1TB SSD',
        'gpu' => 'RTX 4060'
    ]
]);

$id = $product->store(); // store() devuelve ID
echo "Producto creado con ID: $id\n";

// Consultar con filtro JSON
$products = $orm->table('products')
    ->whereRaw("metadata->>'brand' = ?", ['TechBrand'])
    ->getAll();

foreach ($products as $prod) {
    echo "Producto: {$prod['name']} - Precio: \"
{$prod['price']}\"\n";
}
?>
```

## Configuración para SQLite

### Configuración Básica SQLite

```php
<?php
// config/sqlite.php
$config = [
    'driver'   => 'sqlite',
    'database' => __DIR__ . '/../database/app.db',
    'options'  => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]
];

// Crear directorio de base de datos si no existe
$db_dir = dirname($config['database']);
if (!is_dir($db_dir)) {
    mkdir($db_dir, 0755, true);
}

try {
    $orm = new VersaORM($config);
    VersaModel::setORM($orm);

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
$orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
VersaModel::setORM($orm);

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
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
");

$orm->exec("
    CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT,
        category_id INTEGER,
        published BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories(id)
    )
");

// Insertar categoría
$category = VersaModel::dispense('categories');
$category->name = 'Tecnología';
$category->description = 'Artículos sobre tecnología';
$category_id = $category->store(); // ID devuelto

// Insertar artículo
$article = VersaModel::dispense('articles');
$article->title = 'Introducción a VersaORM';
$article->content = 'VersaORM es un ORM simple y potente...';
$article->category_id = $category_id;
$article->published = true;

$article_id = $article->store();
echo "Artículo creado con ID: $article_id\n";

// Consultar con JOIN
$articles = $orm->table('articles')
    ->join('categories', 'articles.category_id', '=', 'categories.id')
    ->select('articles.title', 'categories.name as category')
    ->where('articles.published', '=', true)
    ->getAll();

foreach ($articles as $art) {
    echo "Artículo: {$art['title']} - Categoría: {$art['category']}\n";
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

    $orm = new VersaORM($config);
    VersaModel::setORM($orm);
    return $orm;
    }

    private static function getConfig($name) {
        $configs = [
            'default' => [
                'driver' => 'mysql',
                'host' => 'localhost',
                'database' => 'app_principal',
                'username' => 'root',
                'password' => '',
                'options' => [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
            ],
            'analytics' => [
                'driver' => 'pgsql',
                'host' => 'analytics-server',
                'database' => 'analytics_db',
                'username' => 'analytics_user',
                'password' => 'analytics_pass'
            ],
            'cache' => [
                'driver' => 'sqlite',
                'database' => __DIR__ . '/../database/cache.db'
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
        $required_vars = ['DB_HOST', 'DB_DATABASE', 'DB_USERNAME', 'DB_PASSWORD'];
        foreach ($required_vars as $var) {
            if (empty($_ENV[$var])) {
                throw new Exception("Variable de entorno requerida no encontrada: $var");
            }
        }

        $config = [
            'driver'   => 'mysql',
            'host'     => $_ENV['DB_HOST'],
            'port'     => $_ENV['DB_PORT'] ?? 3306,
            'database' => $_ENV['DB_DATABASE'],
            'username' => $_ENV['DB_USERNAME'],
            'password' => $_ENV['DB_PASSWORD'],
            'charset'  => 'utf8mb4',
            'options'  => [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_PERSISTENT => true,  // Conexiones persistentes
                PDO::ATTR_TIMEOUT => 10,       // Timeout más corto
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4",
                PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true
            ]
        ];

        try {
            $orm = new VersaORM($config);
            VersaModel::setORM($orm);

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
            $orm = new VersaORM(['driver' => 'mysql', 'host' => 'localhost', 'database' => 'test', 'username' => 'root', 'password' => '']);
            VersaModel::setORM($orm);
            $result = $orm->getCell("SELECT 'MySQL OK' as test");
            echo "   ✅ MySQL: $result\n";
        } catch (Exception $e) {
            echo "   ❌ MySQL: " . $e->getMessage() . "\n";
        }
    }

    private function testPostgreSQL() {
        echo "2. Probando PostgreSQL...\n";
        try {
            $orm = new VersaORM(['driver' => 'postgresql', 'host' => 'localhost', 'database' => 'test', 'username' => 'postgres', 'password' => '']);
            VersaModel::setORM($orm);
            $result = $orm->getCell("SELECT 'PostgreSQL OK' as test");
            echo "   ✅ PostgreSQL: $result\n";
        } catch (Exception $e) {
            echo "   ❌ PostgreSQL: " . $e->getMessage() . "\n";
        }
    }

    private function testSQLite() {
        echo "3. Probando SQLite...\n";
        try {
            $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
            VersaModel::setORM($orm);
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
$orm = new VersaORM(['driver' => 'sqlite', 'database' => $db_path]);

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

$orm = new VersaORM($config);
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
$orm = new VersaORM($config);
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
