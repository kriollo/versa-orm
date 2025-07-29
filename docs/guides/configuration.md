# Configuración de VersaORM

Esta guía detalla todas las opciones de configuración disponibles para VersaORM y cómo configurar el ORM para diferentes entornos.

## Tabla de Contenidos

- [Configuración Básica](#configuración-básica)
- [Configuraciones por Driver](#configuraciones-por-driver)
- [Configuración de Entornos](#configuración-de-entornos)
- [Configuraciones Avanzadas](#configuraciones-avanzadas)
- [Validación de Configuración](#validación-de-configuración)

---

## Configuración Básica

### Configuración Mínima

```php
use VersaORM\VersaORM;

$config = [
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_aplicacion',
    'username' => 'usuario',
    'password' => 'contraseña'
];

$orm = new VersaORM($config);
```

### Estructura Completa de Configuración

```php
$config = [
    // Driver de base de datos (requerido)
    'driver' => 'mysql',
    
    // Conexión (requeridos)
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_bd',
    'username' => 'usuario',
    'password' => 'contraseña',
    
    // Configuraciones opcionales
    'charset' => 'utf8mb4',
    'collation' => 'utf8mb4_unicode_ci',
    'timezone' => '+00:00',
    
    // Configuraciones de conexión
    'options' => [
        'timeout' => 30,
        'retry_attempts' => 3,
        'ssl_mode' => 'preferred'
    ]
];
```

---

## Configuraciones por Driver

### MySQL

```php
$mysqlConfig = [
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_app',
    'username' => 'root',
    'password' => 'password',
    'charset' => 'utf8mb4',
    'collation' => 'utf8mb4_unicode_ci',
    'timezone' => '+00:00',
    'options' => [
        'sql_mode' => 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO',
        'timeout' => 60,
        'ssl_mode' => 'preferred'
    ]
];
```

### PostgreSQL

```php
$postgresConfig = [
    'driver' => 'postgresql',
    'host' => 'localhost',
    'port' => 5432,
    'database' => 'mi_app',
    'username' => 'postgres',
    'password' => 'password',
    'schema' => 'public',
    'charset' => 'utf8',
    'options' => [
        'application_name' => 'VersaORM_App',
        'timeout' => 30,
        'sslmode' => 'prefer'
    ]
];
```

### SQLite

```php
$sqliteConfig = [
    'driver' => 'sqlite',
    'database' => '/path/to/database.sqlite',
    'options' => [
        'timeout' => 30,
        'journal_mode' => 'WAL',
        'synchronous' => 'NORMAL'
    ]
];
```

### SQL Server

```php
$sqlServerConfig = [
    'driver' => 'sqlserver',
    'host' => 'localhost',
    'port' => 1433,
    'database' => 'mi_app',
    'username' => 'sa',
    'password' => 'password',
    'charset' => 'utf8',
    'options' => [
        'encrypt' => true,
        'trust_server_certificate' => true,
        'timeout' => 30
    ]
];
```

---

## Configuración de Entornos

### Usando Variables de Entorno

```php
// .env file
DB_DRIVER=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=mi_aplicacion
DB_USER=usuario
DB_PASS=contraseña
DB_CHARSET=utf8mb4

// config.php
$config = [
    'driver' => $_ENV['DB_DRIVER'] ?? 'mysql',
    'host' => $_ENV['DB_HOST'] ?? 'localhost',
    'port' => (int)($_ENV['DB_PORT'] ?? 3306),
    'database' => $_ENV['DB_NAME'] ?? '',
    'username' => $_ENV['DB_USER'] ?? '',
    'password' => $_ENV['DB_PASS'] ?? '',
    'charset' => $_ENV['DB_CHARSET'] ?? 'utf8mb4'
];
```

### Configuración por Entorno

```php
class DatabaseConfig
{
    public static function get(string $environment = 'production'): array
    {
        $configs = [
            'development' => [
                'driver' => 'mysql',
                'host' => 'localhost',
                'port' => 3306,
                'database' => 'mi_app_dev',
                'username' => 'dev_user',
                'password' => 'dev_pass',
                'options' => [
                    'timeout' => 10,
                    'debug_mode' => true
                ]
            ],
            
            'testing' => [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'options' => [
                    'foreign_keys' => true
                ]
            ],
            
            'staging' => [
                'driver' => 'mysql',
                'host' => 'staging-db.ejemplo.com',
                'port' => 3306,
                'database' => 'mi_app_staging',
                'username' => 'staging_user',
                'password' => getenv('STAGING_DB_PASS'),
                'options' => [
                    'timeout' => 30,
                    'ssl_mode' => 'required'
                ]
            ],
            
            'production' => [
                'driver' => 'mysql',
                'host' => 'prod-db.ejemplo.com',
                'port' => 3306,
                'database' => 'mi_app_prod',
                'username' => getenv('PROD_DB_USER'),
                'password' => getenv('PROD_DB_PASS'),
                'options' => [
                    'timeout' => 60,
                    'retry_attempts' => 5,
                    'ssl_mode' => 'required',
                    'ssl_cert' => '/path/to/client-cert.pem',
                    'ssl_key' => '/path/to/client-key.pem',
                    'ssl_ca' => '/path/to/ca-cert.pem'
                ]
            ]
        ];
        
        return $configs[$environment] ?? $configs['production'];
    }
}

// Uso
$config = DatabaseConfig::get(getenv('APP_ENV') ?: 'production');
$orm = new VersaORM($config);
```

---

## Configuraciones Avanzadas

### Pool de Conexiones

```php
class ConnectionPool
{
    private static array $connections = [];
    
    public static function get(string $name = 'default'): VersaORM
    {
        if (!isset(self::$connections[$name])) {
            $config = self::getConfig($name);
            self::$connections[$name] = new VersaORM($config);
        }
        
        return self::$connections[$name];
    }
    
    private static function getConfig(string $name): array
    {
        $configs = [
            'default' => [
                'driver' => 'mysql',
                'host' => 'primary-db.ejemplo.com',
                'database' => 'main_db',
                // ... otras configuraciones
            ],
            
            'analytics' => [
                'driver' => 'postgresql',
                'host' => 'analytics-db.ejemplo.com',
                'database' => 'analytics_db',
                // ... otras configuraciones
            ],
            
            'cache' => [
                'driver' => 'sqlite',
                'database' => '/tmp/cache.sqlite',
                // ... otras configuraciones
            ]
        ];
        
        return $configs[$name] ?? $configs['default'];
    }
}

// Uso
$mainOrm = ConnectionPool::get('default');
$analyticsOrm = ConnectionPool::get('analytics');
$cacheOrm = ConnectionPool::get('cache');
```

### Configuración con Factory

```php
class ORMFactory
{
    private array $config;
    
    public function __construct(array $config)
    {
        $this->config = $config;
    }
    
    public function create(): VersaORM
    {
        // Validar configuración
        $this->validateConfig();
        
        // Aplicar configuraciones por defecto
        $config = array_merge($this->getDefaults(), $this->config);
        
        // Crear instancia
        return new VersaORM($config);
    }
    
    private function validateConfig(): void
    {
        $required = ['driver', 'host', 'database', 'username'];
        
        foreach ($required as $field) {
            if (empty($this->config[$field])) {
                throw new InvalidArgumentException("Campo requerido faltante: {$field}");
            }
        }
    }
    
    private function getDefaults(): array
    {
        return [
            'port' => 3306,
            'charset' => 'utf8mb4',
            'options' => [
                'timeout' => 30,
                'retry_attempts' => 3
            ]
        ];
    }
}

// Uso
$factory = new ORMFactory([
    'driver' => 'mysql',
    'host' => 'localhost',
    'database' => 'mi_app',
    'username' => 'usuario',
    'password' => 'contraseña'
]);

$orm = $factory->create();
```

### Configuración con SSL

```php
$sslConfig = [
    'driver' => 'mysql',
    'host' => 'secure-db.ejemplo.com',
    'port' => 3306,
    'database' => 'secure_app',
    'username' => 'secure_user',
    'password' => 'secure_password',
    'options' => [
        'ssl_mode' => 'required',
        'ssl_cert' => '/path/to/client-cert.pem',
        'ssl_key' => '/path/to/client-key.pem',
        'ssl_ca' => '/path/to/ca-cert.pem',
        'ssl_capath' => '/path/to/cacerts',
        'ssl_cipher' => 'DHE-RSA-AES256-SHA',
        'ssl_verify_server_cert' => true
    ]
];
```

---

## Validación de Configuración

### Validador de Configuración

```php
class ConfigValidator
{
    private array $rules = [
        'driver' => ['required', 'in:mysql,postgresql,sqlite,sqlserver'],
        'host' => ['required_unless:driver,sqlite'],
        'port' => ['integer', 'min:1', 'max:65535'],
        'database' => ['required'],
        'username' => ['required_unless:driver,sqlite'],
        'password' => ['string'],
        'charset' => ['string'],
        'options.timeout' => ['integer', 'min:1']
    ];
    
    public function validate(array $config): array
    {
        $errors = [];
        
        foreach ($this->rules as $field => $rules) {
            $value = $this->getValue($config, $field);
            
            foreach ($rules as $rule) {
                if (!$this->validateRule($value, $rule, $config)) {
                    $errors[] = "Campo {$field} no cumple la regla: {$rule}";
                }
            }
        }
        
        return $errors;
    }
    
    private function getValue(array $config, string $field)
    {
        $keys = explode('.', $field);
        $value = $config;
        
        foreach ($keys as $key) {
            $value = $value[$key] ?? null;
        }
        
        return $value;
    }
    
    private function validateRule($value, string $rule, array $config): bool
    {
        switch ($rule) {
            case 'required':
                return !empty($value);
                
            case str_starts_with($rule, 'required_unless:'):
                [$field, $exceptValue] = explode(',', substr($rule, 16));
                return $config[$field] === $exceptValue || !empty($value);
                
            case str_starts_with($rule, 'in:'):
                $allowedValues = explode(',', substr($rule, 3));
                return in_array($value, $allowedValues);
                
            case 'integer':
                return is_int($value) || (is_string($value) && ctype_digit($value));
                
            case str_starts_with($rule, 'min:'):
                $min = (int)substr($rule, 4);
                return (int)$value >= $min;
                
            case str_starts_with($rule, 'max:'):
                $max = (int)substr($rule, 4);
                return (int)$value <= $max;
                
            case 'string':
                return is_string($value);
                
            default:
                return true;
        }
    }
}

// Uso
$validator = new ConfigValidator();
$errors = $validator->validate($config);

if (!empty($errors)) {
    throw new InvalidArgumentException('Errores de configuración: ' . implode(', ', $errors));
}
```

### Test de Conexión

```php
class ConnectionTester
{
    public static function test(array $config): array
    {
        $results = [
            'success' => false,
            'message' => '',
            'details' => []
        ];
        
        try {
            // Crear instancia temporal
            $orm = new VersaORM($config);
            
            // Test básico de conexión
            $version = $orm->exec('SELECT VERSION() as version')[0]['version'];
            
            $results['success'] = true;
            $results['message'] = 'Conexión exitosa';
            $results['details'] = [
                'database_version' => $version,
                'orm_version' => $orm->version(),
                'connection_time' => microtime(true)
            ];
            
        } catch (Exception $e) {
            $results['message'] = 'Error de conexión: ' . $e->getMessage();
            $results['details'] = [
                'error_code' => $e->getCode(),
                'error_type' => get_class($e)
            ];
        }
        
        return $results;
    }
}

// Uso
$testResult = ConnectionTester::test($config);

if (!$testResult['success']) {
    echo "Error: " . $testResult['message'];
} else {
    echo "Conexión exitosa. Versión BD: " . $testResult['details']['database_version'];
}
```

---

## Configuración de Logging

```php
class ORMLogger
{
    private $logFile;
    
    public function __construct(string $logFile = 'orm.log')
    {
        $this->logFile = $logFile;
    }
    
    public function createLoggingORM(array $config): VersaORM
    {
        $orm = new VersaORM($config);
        
        // Wrapper para logging (esto requeriría extensión del ORM)
        return new LoggingORMWrapper($orm, $this);
    }
    
    public function log(string $level, string $message, array $context = []): void
    {
        $timestamp = date('Y-m-d H:i:s');
        $contextStr = !empty($context) ? json_encode($context) : '';
        
        $logEntry = "[{$timestamp}] {$level}: {$message} {$contextStr}\n";
        
        file_put_contents($this->logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }
}
```

---

## Mejores Prácticas

### 1. Seguridad

```php
// ✅ Usar variables de entorno para credenciales
$config = [
    'username' => getenv('DB_USER'),
    'password' => getenv('DB_PASS')
];

// ❌ No hardcodear credenciales
$config = [
    'username' => 'root',
    'password' => '123456'
];
```

### 2. Configuración por Capas

```php
// 1. Configuración base
$baseConfig = require 'config/database.php';

// 2. Configuración de entorno
$envConfig = require "config/database.{$environment}.php";

// 3. Configuración local (no en VCS)
$localConfig = file_exists('config/database.local.php') 
    ? require 'config/database.local.php' 
    : [];

// 4. Merge de configuraciones
$config = array_merge($baseConfig, $envConfig, $localConfig);
```

### 3. Validación Temprana

```php
// Validar configuración al inicio de la aplicación
$validator = new ConfigValidator();
$errors = $validator->validate($config);

if (!empty($errors)) {
    // Log errores y terminar ejecución
    error_log('Errores de configuración: ' . implode(', ', $errors));
    exit(1);
}
```

### 4. Monitoreo de Conexión

```php
// Verificar conexión periódicamente
register_shutdown_function(function() use ($orm) {
    if ($orm && !$orm->disconnect()) {
        error_log('Advertencia: No se pudo desconectar limpiamente de la base de datos');
    }
});
```

---

Esta guía cubre todas las opciones de configuración disponibles en VersaORM. Para casos específicos o configuraciones personalizadas, consulta la documentación de tu driver de base de datos específico.
