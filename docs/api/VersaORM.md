# VersaORM Class

La clase `VersaORM` es el núcleo principal del ORM, encargada de manejar la comunicación con el binario de Rust y proporcionar una API fluida para operaciones de base de datos.

## Tabla de Contenidos

- [Constructor](#constructor)
- [Configuración](#configuración)
- [Query Builder](#query-builder)
- [Métodos Estilo RedBean](#métodos-estilo-redbean)
- [Consultas Raw](#consultas-raw)
- [Schema y Cache](#schema-y-cache)
- [Utilidades](#utilidades)
- [Manejo de Errores](#manejo-de-errores)

---

## Constructor

### `__construct(array $config = [])`

Crea una nueva instancia de VersaORM.

**Parámetros:**
- `$config` (array, opcional): Configuración de la base de datos

**Ejemplo:**
```php
$orm = new VersaORM([
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_aplicacion',
    'username' => 'usuario',
    'password' => 'contraseña'
]);
```

---

## Configuración

### `setConfig(array $config): void`

Establece la configuración de la base de datos para la instancia.

**Parámetros:**
- `$config` (array): Array asociativo con la configuración

**Ejemplo:**
```php
$orm->setConfig([
    'driver' => 'postgresql',
    'host' => 'localhost',
    'port' => 5432,
    'database' => 'mi_bd',
    'username' => 'postgres',
    'password' => 'mi_password'
]);
```

### `getConfig(): array`

Obtiene la configuración actual de la instancia.

**Retorna:** Array con la configuración actual

**Ejemplo:**
```php
$config = $orm->getConfig();
echo $config['host']; // localhost
```

---

## Query Builder

### `table(string $table): QueryBuilder`

Crea una instancia de QueryBuilder para la tabla especificada.

**Parámetros:**
- `$table` (string): Nombre de la tabla

**Retorna:** Instancia de `QueryBuilder`

**Ejemplo:**
```php
$users = $orm->table('users')
    ->where('active', '=', 1)
    ->orderBy('created_at', 'desc')
    ->findAll();
```

---

## Métodos Estilo RedBean

### `count(string $table, ?string $conditions = null, array $bindings = []): int`

Cuenta registros en una tabla con condiciones opcionales.

**Parámetros:**
- `$table` (string): Nombre de la tabla
- `$conditions` (string|null, opcional): Condiciones WHERE
- `$bindings` (array, opcional): Valores para prepared statements

**Retorna:** Número de registros (int)

**Ejemplos:**
```php
// Contar todos los usuarios
$total = $orm->count('users');

// Contar usuarios activos
$active = $orm->count('users', 'status = ?', ['active']);

// Contar con múltiples condiciones
$recent = $orm->count('users', 'status = ? AND created_at > ?', ['active', '2024-01-01']);
```

### `getAll(string $sql, array $bindings = []): array`

Ejecuta una consulta SQL y devuelve todos los registros como array de arrays.

**Parámetros:**
- `$sql` (string): Consulta SQL
- `$bindings` (array, opcional): Valores para prepared statements

**Retorna:** Array de arrays con los datos

**Ejemplo:**
```php
$users = $orm->getAll('SELECT * FROM users WHERE age > ?', [18]);
foreach ($users as $user) {
    echo $user['name'] . "\n";
}
```

### `getRow(string $sql, array $bindings = []): ?array`

Obtiene una sola fila como array.

**Parámetros:**
- `$sql` (string): Consulta SQL
- `$bindings` (array, opcional): Valores para prepared statements

**Retorna:** Array con los datos o null si no hay resultados

**Ejemplo:**
```php
$user = $orm->getRow('SELECT * FROM users WHERE id = ?', [1]);
if ($user) {
    echo "Usuario: " . $user['name'];
}
```

### `getCell(string $sql, array $bindings = []): mixed`

Obtiene un solo valor de una consulta.

**Parámetros:**
- `$sql` (string): Consulta SQL
- `$bindings` (array, opcional): Valores para prepared statements

**Retorna:** El valor de la primera columna de la primera fila

**Ejemplos:**
```php
// Obtener el nombre de un usuario
$name = $orm->getCell('SELECT name FROM users WHERE id = ?', [1]);

// Obtener el conteo
$count = $orm->getCell('SELECT COUNT(*) FROM users WHERE active = 1');

// Obtener el último ID insertado
$lastId = $orm->getCell('SELECT MAX(id) FROM users');
```

### `findOne(string $table, $id, string $pk = 'id'): ?Model`

Busca un registro por ID y lo devuelve como modelo.

**Parámetros:**
- `$table` (string): Nombre de la tabla
- `$id` (mixed): Valor del ID a buscar
- `$pk` (string, opcional): Nombre de la clave primaria (por defecto 'id')

**Retorna:** Instancia de `Model` o null si no se encuentra

**Ejemplos:**
```php
// Buscar por ID
$user = $orm->findOne('users', 1);
if ($user) {
    echo $user->name;
}

// Buscar por clave primaria personalizada
$product = $orm->findOne('products', 'SKU123', 'sku');
```

### `findAll(string $table, ?string $conditions = null, array $bindings = []): Model[]`

Busca registros con condiciones y los devuelve como array de modelos.

**Parámetros:**
- `$table` (string): Nombre de la tabla
- `$conditions` (string|null, opcional): Condiciones WHERE
- `$bindings` (array, opcional): Valores para prepared statements

**Retorna:** Array de instancias de `Model`

**Ejemplos:**
```php
// Obtener todos los usuarios
$users = $orm->findAll('users');

// Obtener usuarios activos
$activeUsers = $orm->findAll('users', 'status = ?', ['active']);

// Obtener usuarios con múltiples condiciones
$recentUsers = $orm->findAll('users', 'status = ? AND created_at > ?', ['active', '2024-01-01']);
```

### `dispense(string $table): Model`

Crea un nuevo modelo vacío para una tabla.

**Parámetros:**
- `$table` (string): Nombre de la tabla

**Retorna:** Nueva instancia de `Model`

**Ejemplo:**
```php
$user = $orm->dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan@ejemplo.com';
$user->status = 'active';
$orm->store($user);
```

### `store(Model $model): void`

Guarda un modelo (INSERT o UPDATE automático).

**Parámetros:**
- `$model` (Model): Instancia del modelo a guardar

**Ejemplo:**
```php
// Crear nuevo usuario
$user = $orm->dispense('users');
$user->name = 'Ana García';
$user->email = 'ana@ejemplo.com';
$orm->store($user); // INSERT

// Modificar usuario existente
$user->name = 'Ana García López';
$orm->store($user); // UPDATE
```

### `trash(Model $model): void`

Elimina un modelo de la base de datos.

**Parámetros:**
- `$model` (Model): Instancia del modelo a eliminar

**Ejemplo:**
```php
$user = $orm->findOne('users', 1);
if ($user) {
    $orm->trash($user);
    echo "Usuario eliminado";
}
```

---

## Consultas Raw

### `exec(string $query, array $bindings = []): mixed`

Ejecuta una consulta SQL personalizada.

**Parámetros:**
- `$query` (string): Consulta SQL
- `$bindings` (array, opcional): Valores para prepared statements

**Retorna:** Resultado de la consulta (dependiente del tipo de consulta)

**Ejemplos:**
```php
// SELECT
$users = $orm->exec('SELECT * FROM users WHERE age > ?', [21]);

// INSERT
$orm->exec('INSERT INTO logs (message, created_at) VALUES (?, NOW())', ['Usuario creado']);

// UPDATE
$orm->exec('UPDATE users SET last_login = NOW() WHERE id = ?', [1]);

// DELETE
$orm->exec('DELETE FROM sessions WHERE expires_at < NOW()');

// Consulta compleja
$stats = $orm->exec('
    SELECT 
        DATE(created_at) as date,
        COUNT(*) as total_users,
        AVG(age) as avg_age
    FROM users 
    WHERE created_at >= ? 
    GROUP BY DATE(created_at)
    ORDER BY date DESC
', ['2024-01-01']);
```

### `raw(string $query, array $bindings = []): mixed`

Método alias para compatibilidad con código existente.

**Parámetros:**
- `$query` (string): Consulta SQL
- `$bindings` (array, opcional): Valores para prepared statements

**Retorna:** Resultado de la consulta

**Nota:** Método deprecado, usar `exec()` en su lugar.

---

## Schema y Cache

### `schema(string $subject, ?string $tableName = null): mixed`

Obtiene información del esquema de la base de datos.

**Parámetros:**
- `$subject` (string): Tipo de información a obtener
- `$tableName` (string|null, opcional): Nombre de la tabla específica

**Retorna:** Información del esquema

**Ejemplos:**
```php
// Obtener lista de tablas
$tables = $orm->schema('tables');

// Obtener columnas de una tabla
$columns = $orm->schema('columns', 'users');

// Obtener índices de una tabla
$indexes = $orm->schema('indexes', 'users');

// Obtener claves foráneas
$foreignKeys = $orm->schema('foreign_keys', 'orders');
```

### `cache(string $action): mixed`

Administra el caché interno del ORM.

**Parámetros:**
- `$action` (string): Acción a realizar ('clear', 'status', etc.)

**Retorna:** Resultado de la operación de caché

**Ejemplos:**
```php
// Limpiar caché
$orm->cache('clear');

// Obtener estado del caché
$status = $orm->cache('status');

// Obtener estadísticas
$stats = $orm->cache('stats');
```

---

## Utilidades

### `version(): string`

Obtiene la versión actual de VersaORM.

**Retorna:** String con la versión

**Ejemplo:**
```php
echo "VersaORM v" . $orm->version(); // VersaORM v1.0.0
```

### `disconnect(): bool`

Cierra la conexión a la base de datos.

**Retorna:** true si la desconexión fue exitosa

**Ejemplo:**
```php
$orm->disconnect();
echo "Conexión cerrada";
```

---

## Manejo de Errores

VersaORM proporciona manejo de errores detallado con sugerencias automáticas:

### Tipos de Errores Manejados

1. **Errores de Conexión**
   - Servidor de base de datos no disponible
   - Credenciales incorrectas
   - Problemas de red

2. **Errores de Esquema**
   - Tabla no encontrada
   - Columna no encontrada
   - Errores de sintaxis SQL

3. **Errores de Datos**
   - Violación de restricciones
   - Tipos de datos incorrectos
   - Valores duplicados

4. **Errores de Permisos**
   - Acceso denegado
   - Permisos insuficientes

### Ejemplo de Manejo de Errores

```php
try {
    $user = $orm->findOne('usuarios', 1); // Tabla no existe
} catch (Exception $e) {
    echo $e->getMessage();
    /*
    Salida:
    VersaORM Error [TABLE_NOT_FOUND]: Table 'usuarios' doesn't exist
    SQL State: 42S02
    
    Suggestions:
    - Check if the table name is spelled correctly
    - Verify the table exists in the database
    - Check if you have permissions to access the table
    - Ensure you are connected to the correct database
    
    Context: Action=raw, Query=SELECT * FROM usuarios WHERE id = ?
    */
}
```

---

## Ejemplos Avanzados

### Transacciones (usando SQL raw)

```php
try {
    $orm->exec('START TRANSACTION');
    
    // Crear usuario
    $user = $orm->dispense('users');
    $user->name = 'Carlos Ruiz';
    $user->email = 'carlos@ejemplo.com';
    $orm->store($user);
    
    // Crear perfil
    $profile = $orm->dispense('profiles');
    $profile->user_id = $user->id;
    $profile->bio = 'Desarrollador PHP';
    $orm->store($profile);
    
    $orm->exec('COMMIT');
    echo "Usuario y perfil creados exitosamente";
    
} catch (Exception $e) {
    $orm->exec('ROLLBACK');
    echo "Error: " . $e->getMessage();
}
```

### Consultas con JOINs

```php
$usersWithProfiles = $orm->exec('
    SELECT u.*, p.bio, p.avatar
    FROM users u
    LEFT JOIN profiles p ON u.id = p.user_id
    WHERE u.status = ?
    ORDER BY u.created_at DESC
', ['active']);
```

### Preparación para Producción

```php
// Configuración optimizada para producción
$orm = new VersaORM([
    'driver' => 'mysql',
    'host' => getenv('DB_HOST'),
    'port' => (int)getenv('DB_PORT'),
    'database' => getenv('DB_NAME'),
    'username' => getenv('DB_USER'),
    'password' => getenv('DB_PASS'),
    'charset' => 'utf8mb4',
    'options' => [
        'timeout' => 30,
        'retry_attempts' => 3
    ]
]);
```

---

## Consideraciones de Rendimiento

1. **Usar Prepared Statements**: Siempre usar binding de parámetros
2. **Consultas Batch**: Para múltiples inserts, considerar consultas raw
3. **Caché de Schema**: El ORM cachea automáticamente información de esquema
4. **Conexiones Persistentes**: Reutilizar instancias de VersaORM cuando sea posible

---

Esta documentación cubre todos los métodos y funcionalidades de la clase VersaORM. Para ejemplos más específicos, consulta la sección de ejemplos en la documentación.
