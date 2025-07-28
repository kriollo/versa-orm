# 🚀 Guía de Inicio Rápido - VersaORM-PHP

Esta guía te ayudará a configurar y usar VersaORM-PHP en menos de 10 minutos.

## ⚡ Instalación Rápida

### 1. Preparar el entorno

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/versaORM-PHP.git
cd versaORM-PHP

# Compilar el binario de Rust
cd versaorm_cli
cargo build --release
cd ..
```

### 2. Verificar instalación

```bash
# Windows
.\versaorm_cli\target\release\versaorm_cli.exe --help

# Linux/macOS  
./versaorm_cli/target/release/versaorm_cli --help
```

## 🔧 Configuración Básica

### Crear archivo de configuración

```php
<?php
// config.php
// Opción 1: Usar autoloader (RECOMENDADO)
require_once 'php/autoload.php';

// Opción 2: Cargar archivos individualmente
// require_once 'php/VersaORM.php';
// require_once 'php/VersaORMQueryBuilder.php';
// require_once 'php/VersaORMModel.php';

// Configuración de base de datos
$dbConfig = [
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_app',
    'username' => 'root',
    'password' => 'password',
    'charset' => 'utf8mb4'
];

// Conectar
VersaORM::connect($dbConfig);
```

## 📋 Ejemplos Básicos

### 1. Consulta Simple

```php
<?php
require_once 'config.php';

// Obtener todos los usuarios activos
$users = VersaORM::table('users')
    ->where('active', '=', true)
    ->get();

foreach ($users as $user) {
    echo "ID: {$user['id']}, Nombre: {$user['name']}\n";
}
```

### 2. Insertar Datos

```php
<?php
require_once 'config.php';

// Crear un nuevo usuario
$userId = VersaORM::table('users')->insertGetId([
    'name' => 'Juan Pérez',
    'email' => 'juan@example.com',
    'active' => true,
    'created_at' => date('Y-m-d H:i:s')
]);

echo "Usuario creado con ID: $userId\n";
```

### 3. Actualizar Registro

```php
<?php
require_once 'config.php';

// Actualizar usuario
$affected = VersaORM::table('users')
    ->where('id', '=', $userId)
    ->update([
        'name' => 'Juan Carlos Pérez',
        'updated_at' => date('Y-m-d H:i:s')
    ]);

echo "Registros actualizados: $affected\n";
```

### 4. Consulta con Join

```php
<?php
require_once 'config.php';

// Usuarios con sus posts
$usersWithPosts = VersaORM::table('users')
    ->select(['users.name', 'posts.title', 'posts.created_at'])
    ->join('posts', 'users.id', '=', 'posts.user_id')
    ->where('users.active', '=', true)
    ->orderBy('posts.created_at', 'desc')
    ->get();

foreach ($usersWithPosts as $item) {
    echo "{$item['name']}: {$item['title']}\n";
}
```

### 5. Consulta Cruda

```php
<?php
require_once 'config.php';

// Consulta SQL personalizada
$stats = VersaORM::exec('
    SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN active = 1 THEN 1 END) as active_users,
        AVG(DATEDIFF(NOW(), created_at)) as avg_days_since_creation
    FROM users
');

$stat = $stats[0];
echo "Total usuarios: {$stat['total_users']}\n";
echo "Usuarios activos: {$stat['active_users']}\n";
echo "Días promedio desde creación: " . round($stat['avg_days_since_creation']) . "\n";
```

## 🔍 Introspección de Esquema

### Explorar la base de datos

```php
<?php
require_once 'config.php';

// Listar todas las tablas
$tables = VersaORM::schema('tables');
echo "Tablas disponibles:\n";
foreach ($tables as $table) {
    echo "- $table\n";
}

// Obtener estructura de una tabla
$columns = VersaORM::schema('columns', 'users');
echo "\nColumnas de la tabla 'users':\n";
foreach ($columns as $column) {
    echo "- {$column['name']} ({$column['data_type']})";
    if ($column['is_primary_key']) echo " [PK]";
    if (!$column['is_nullable']) echo " [NOT NULL]";
    echo "\n";
}
```

## 🧠 Gestión de Caché

```php
<?php
require_once 'config.php';

// Limpiar caché antes de operaciones importantes
VersaORM::cache('clear');

// Realizar operaciones...
$users = VersaORM::table('users')->get();

// Verificar estado del caché
$cacheSize = VersaORM::cache('status');
echo "Elementos en caché: $cacheSize\n";
```

## 🛠️ Manejo de Errores

```php
<?php
require_once 'config.php';

try {
    // Operación que puede fallar
    $user = VersaORM::table('users')
        ->where('email', '=', 'inexistente@example.com')
        ->firstOrFail(); // Este método no existe, es solo ejemplo
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    
    // Log del error
    error_log("VersaORM Error: " . $e->getMessage());
    
    // Respuesta para el usuario
    echo "Ocurrió un problema con la base de datos. Inténtalo más tarde.\n";
}
```

## 📊 Ejemplos por Tipo de Base de Datos

### MySQL

```php
VersaORM::connect([
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_app',
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
    'database' => 'mi_app',
    'username' => 'usuario',
    'password' => 'contraseña',
    'charset' => 'utf8'
]);
```

### SQLite

```php
VersaORM::connect([
    'driver' => 'sqlite',
    'database' => __DIR__ . '/database.sqlite',
    'username' => '',
    'password' => '',
    'host' => '',
    'port' => 0,
    'charset' => ''
]);
```

## 🎯 Modelos ORM (Estilo RedBeanPHP)

VersaORM incluye funcionalidad estilo RedBeanPHP para trabajar con modelos:

### Crear y Guardar Modelo

```php
<?php
require_once 'config.php';

// Crear nuevo modelo
$user = VersaORM::table('users')->dispense();
$user->name = 'María González';
$user->email = 'maria@example.com';
$user->active = true;
$user->store(); // Guarda en la base de datos

echo "Usuario creado con ID: {$user->id}\n";
```

### Cargar y Actualizar Modelo

```php
<?php
require_once 'config.php';

// Cargar modelo existente
$user = VersaORM::table('users')->dispense();
$user->load(1); // Carga el usuario con ID 1

// Modificar datos
$user->name = 'María Elena González';
$user->updated_at = date('Y-m-d H:i:s');
$user->store(); // Actualiza en la base de datos

echo "Usuario actualizado\n";
```

### Eliminar Modelo

```php
<?php
require_once 'config.php';

// Cargar y eliminar
$user = VersaORM::table('users')->dispense();
$user->load(1);
$user->trash(); // Elimina de la base de datos

echo "Usuario eliminado\n";
```

## 🔌 Gestión de Conexiones

```php
<?php
require_once 'config.php';

// Trabajar con la base de datos
$users = VersaORM::table('users')->get();

// Cerrar conexión cuando termine
VersaORM::disconnect();
echo "Conexión cerrada\n";
```

## 🎯 Siguiente Paso

Una vez que hayas probado estos ejemplos básicos, consulta:

- [Documentación completa](../README.md) para funciones avanzadas
- [Ejemplos completos](../example.php) para casos de uso más complejos
- [Especificaciones técnicas](../rule.md) para detalles de implementación

¡Ya estás listo para usar VersaORM-PHP en tus proyectos! 🎉
