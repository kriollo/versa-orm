# Freeze Mode - Protección de Esquema

Freeze Mode es una característica de seguridad avanzada de VersaORM que protege el esquema de tu base de datos contra modificaciones accidentales o no autorizadas, especialmente útil en entornos de producción.

## ¿Qué es Freeze Mode?

Freeze Mode es un estado de protección que:
- Previene la creación automática de tabla
loquea la modificación de estructura de tablas existentes
- Impide la adición automática de columnas
- Protege contra cambios de esquema no intencionados
- Mantiene la integridad estructural de la base de datos

## Activación de Freeze Mode

### Activación Global

```php
// Configuración básica con Freeze Mode activado
$orm = new VersaORM([
    'host' => 'localhost',
    'database' => 'mi_app_produccion',
    'username' => 'usuario',
    'password' => 'password',
    'freeze' => true  // Activar Freeze Mode globalmente
]);

// O activar después de la inicialización
$orm->freeze(true);
```

### Activación por Entorno

```php
// Configuración basada en entorno
$config = [
    'host' => 'localhost',
    'database' => 'mi_app',
    'username' => 'usuario',
    'password' => 'password'
];

// Activar Freeze Mode solo en producción
if (getenv('APP_ENV') === 'production') {
    $config['freeze'] = true;
}

$orm = new VersaORM($config);
```

### Verificar Estado de Freeze Mode

```php
// Verificar si Freeze Mode está activo
if ($orm->isFrozen()) {
    echo "Base de datos protegida - Freeze Mode activo";
} else {
    echo "Modo desarrollo - Esquema modificable";
}

// Obtener información detallada
$freezeInfo = $orm->getFreezeInfo();
echo "Estado: " . ($freezeInfo['active'] ? 'Activo' : 'Inactivo');
echo "Desde: " . $freezeInfo['activated_at'];
```

## Comportamiento con Freeze Mode Activo

### Creación de Modelos

```php
// Con Freeze Mode DESACTIVADO (desarrollo)
$orm->freeze(false);

$user = VersaModel::dispense('users');  // ✅ Crea tabla automáticamente si no existe
$user->name = 'Juan Pérez';
$user->email = 'juan@example.com';
$user->new_field = 'valor';       // ✅ Agrega columna automáticamente
$$user->store();

// Con Freeze Mode ACTIVADO (producción)
$orm->freeze(true);

$user = VersaModel::dispense('users');  // ✅ OK si la tabla ya existe
$user->name = 'Ana García';
$user->email = 'ana@example.com';

try {
    $user->new_field = 'valor';   // ❌ Error: columna no existe
    $$user->store();
} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage();
    // Error: Columna 'new_field' no existe en tabla 'users' (Freeze Mode activo)
}
```

### Operaciones Permitidas y Bloqueadas

```php
$orm->freeze(true);

// ✅ OPERACIONES PERMITIDAS en Freeze Mode:

// 1. CRUD en tablas existentes con columnas existentes
$user = VersaModel::load('users', 1);
$user->name = 'Nombre actualizado';  // ✅ Columna existe
$$user->store();

// 2. Consultas normales
$users = VersaModel::findAll('users', 'active = ?', [true]); // ✅ OK

// 3. Relaciones entre tablas existentes
$posts = $user->ownPostsList;  // ✅ OK si las tablas existen

// ❌ OPERACIONES BLOQUEADAS en Freeze Mode:

try {
    // 1. Crear nuevas tablas
    $newModel = VersaModel::dispense('nueva_tabla');
    $$newModel->store();  // ❌ Error
} catch (VersaORMException $e) {
    echo "Bloqueado: " . $e->getMessage();
}

try {
    // 2. Agregar nuevas columnas
    $user = VersaModel::load('users', 1);
    $user->nueva_columna = 'valor';
    $$user->store();  // ❌ Error
} catch (VersaORMException $e) {
    echo "Bloqueado: " . $e->getMessage();
}
```

## Configuración Avanzada de Freeze Mode

### Freeze Mode Selectivo

```php
class SelectiveFreezeORM extends VersaORM {
    // Tablas que están congeladas (no se pueden modificar)
    protected $frozenTables = [
        'users',
        'orders',
        'products',
        'categories'
    ];

    // Tablas que pueden modificarse incluso en Freeze Mode
    protected $unfrozenTables = [
        'logs',
        'cache',
        'sessions',
        'temp_data'
    ];

    public function isTableFrozen($table) {
        if (in_array($table, $this->unfrozenTables)) {
            return false;
        }

        if (in_array($table, $this->frozenTables)) {
            return true;
        }

        // Por defecto, seguir el estado global de freeze
        return $this->isFrozen();
    }

    public function dispense($table) {
        if ($this->isTableFrozen($table) && !$this->tableExists($table)) {
            throw new VersaORMException("No se puede crear la tabla '$table' - está congelada");
        }

        return parent::dispense($table);
    }
}
```

### Freeze Mode con Excepciones

```php
class FlexibleFreezeORM extends VersaORM {
    private $temporaryUnfreeze = false;

    // Descongelar temporalmente para operaciones específicas
    public function withUnfreeze(callable $callback) {
        $originalState = $this->isFrozen();

        try {
            $this->freeze(false);
            $this->temporaryUnfreeze = true;

            $result = $callback($this);

            return $result;

        } finally {
            $this->freeze($originalState);
            $this->temporaryUnfreeze = false;
        }
    }

    // Permitir modificaciones de esquema con autorización
    public function authorizedSchemaChange(callable $callback, $authToken) {
        if (!$this->validateAuthToken($authToken)) {
            throw new VersaORMException('Token de autorización inválido');
        }

        return $this->withUnfreeze($callback);
    }

    private function validateAuthToken($token) {
        // Validar token de autorización (implementar según necesidades)
        return hash_equals(getenv('SCHEMA_CHANGE_TOKEN'), $token);
    }
}

// Uso de descongelamiento temporal
$result = $orm->withUnfreeze(function($orm) {
    // Dentro de este bloque, se pueden hacer cambios de esquema
    $newModel = VersaModel::dispense('nueva_tabla_temporal');
    $newModel->data = 'información temporal';
    return $$newModel->store();
});
```

## Migración de Esquemas con Freeze Mode

### Sistema de Migraciones

```php
class MigrationManager {
    private $orm;
    private $migrationsPath;

    public function __construct(VersaORM $orm, $migrationsPath) {
        $this->orm = $orm;
        $this->migrationsPath = $migrationsPath;
    }

    public function runMigrations() {
        // Verificar si hay migraciones pendientes
        $pendingMigrations = $this->getPendingMigrations();

        if (empty($pendingMigrations)) {
            echo "No hay migraciones pendientes\n";
            return;
        }

        // Desactivar Freeze Mode temporalmente para migraciones
        $originalFreezeState = $this->orm->isFrozen();
        $this->orm->freeze(false);

        try {
            foreach ($pendingMigrations as $migration) {
                echo "Ejecutando migración: {$migration['name']}\n";
                $this->runMigration($migration);
                $this->markMigrationAsRun($migration);
            }

            echo "Todas las migraciones ejecutadas exitosamente\n";

        } finally {
            // Restaurar estado original de Freeze Mode
            $this->orm->freeze($originalFreezeState);
        }
    }

    private function runMigration($migration) {
        require_once $this->migrationsPath . '/' . $migration['file'];

        $className = $migration['class'];
        $migrationInstance = new $className($this->orm);
        $migrationInstance->up();
    }

    private function getPendingMigrations() {
        // Implementar lógica para obtener migraciones pendientes
        // Comparar archivos de migración con tabla de migraciones ejecutadas
        return [];
    }

    private function markMigrationAsRun($migration) {
        // Marcar migración como ejecutada en tabla de control
        $record = $this->orm->dispense('migrations');
        $record->name = $migration['name'];
        $record->executed_at = date('Y-m-d H:i:s');
        $this->orm->store($record);
    }
}
```

### Ejemplo de Migración

```php
class CreateProductsTable {
    private $orm;

    public function __construct(VersaORM $orm) {
        $this->orm = $orm;
    }

    public function up() {
        // Esta migración se ejecuta con Freeze Mode desactivado
        $product = $this->orm->dispense('products');
        $product->name = '';
        $product->description = '';
        $product->price = 0.0;
        $product->category_id = 0;
        $product->active = true;
        $product->created_at = date('Y-m-d H:i:s');

        // Esto creará la tabla con las columnas necesarias
        $this->orm->store($product);
        $this->orm->trash($product); // Eliminar el registro temporal

        echo "Tabla 'products' creada exitosamente\n";
    }

    public function down() {
        // Rollback de la migración
        $this->orm->wipe('products');
        echo "Tabla 'products' eliminada\n";
    }
}
```

## Monitoreo y Auditoría

### Log de Intentos Bloqueados

```php
class AuditedFreezeORM extends VersaORM {
    public function store($model) {
        try {
            return parent::store($model);

        } catch (VersaORMException $e) {
            // Si el error es por Freeze Mode, registrarlo
            if (strpos($e->getMessage(), 'Freeze Mode') !== false) {
                $this->logBlockedAttempt($model, $e->getMessage());
            }

            throw $e;
        }
    }

    private function logBlockedAttempt($model, $error) {
        // Registrar intento bloqueado para auditoría
        $log = [
            'timestamp' => date('Y-m-d H:i:s'),
            'table' => $model->getMeta('type'),
            'action' => 'blocked_schema_change',
            'error' => $error,
            'user_ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];

        error_log("FREEZE_MODE_BLOCK: " . json_encode($log));

        // También guardar en base de datos si es posible
        try {
            $auditLog = $this->dispense('security_logs');
            $auditLog->type = 'freeze_mode_block';
            $auditLog->details = json_encode($log);
            $auditLog->created_at = date('Y-m-d H:i:s');

            // Temporalmente desactivar freeze para guardar el log
            $this->freeze(false);
            $this->store($auditLog);
            $this->freeze(true);

        } catch (Exception $e) {
            // Si no se puede guardar en BD, al menos está en error_log
        }
    }
}
```

### Dashboard de Estado

```php
class FreezeModeDashboard {
    private $orm;

    public function __construct(VersaORM $orm) {
        $this->orm = $orm;
    }

    public function getStatus() {
        return [
            'freeze_active' => $this->orm->isFrozen(),
            'total_tables' => $this->getTotalTables(),
            'protected_tables' => $this->getProtectedTables(),
            'recent_blocks' => $this->getRecentBlocks(),
            'last_schema_change' => $this->getLastSchemaChange()
        ];
    }

    private function getTotalTables() {
        // Obtener número total de tablas
        $result = $this->orm->getAll("SHOW TABLES");
        return count($result);
    }

    private function getProtectedTables() {
        // Listar tablas que están protegidas por Freeze Mode
        if (!$this->orm->isFrozen()) {
            return [];
        }

        $result = $this->orm->getAll("SHOW TABLES");
        return array_column($result, 'Tables_in_' . $this->orm->getDatabase());
    }

    private function getRecentBlocks() {
        // Obtener intentos bloqueados recientes
        try {
            return $this->orm->findAll('security_logs',
                'type = ? AND created_at > ? ORDER BY created_at DESC LIMIT 10',
                ['freeze_mode_block', date('Y-m-d H:i:s', strtotime('-24 hours'))]
            );
        } catch (Exception $e) {
            return [];
        }
    }

    private function getLastSchemaChange() {
        // Obtener información del último cambio de esquema
        try {
            $migration = $this->orm->findOne('migrations',
                'ORDER BY executed_at DESC LIMIT 1'
            );
            return $migration ? $migration->executed_at : null;
        } catch (Exception $e) {
            return null;
        }
    }
}
```

## Mejores Prácticas

### 1. Activar en Producción

```php
// ✅ Buena práctica: Freeze Mode en producción
if (getenv('APP_ENV') === 'production') {
    $orm->freeze(true);
}

// ✅ También buena práctica: Configuración por archivo
$config = require 'config/database.php';
$orm = new VersaORM($config);
```

### 2. Usar Migraciones para Cambios de Esquema

```php
// ✅ Buena práctica: Cambios controlados con migraciones
class AddEmailVerificationToUsers {
    public function up() {
        // Cambio de esquema controlado
        $user = $this->orm->dispense('users');
        $user->email_verified_at = null;
        $this->orm->store($user);
        $this->orm->trash($user);
    }
}

// ❌ Evitar: Cambios de esquema en código de aplicación
$user = VersaModel::load('users', 1);
$user->new_column = 'value'; // Esto fallará en producción con Freeze Mode
```

### 3. Monitorear Intentos Bloqueados

```php
// ✅ Buena práctica: Registrar y monitorear intentos bloqueados
class MonitoredORM extends VersaORM {
    public function store($model) {
        try {
            return parent::store($model);
        } catch (VersaORMException $e) {
            if ($this->isFreezeError($e)) {
                $this->notifyAdmins($e, $model);
            }
            throw $e;
        }
    }
}
```

### 4. Documentar Esquema Protegido

```php
/**
 * Tablas protegidas por Freeze Mode en producción:
 *
 * - users: Información de usuarios del sistema
 * - orders: Órdenes de compra y transacciones
 * - products: Catálogo de productos
 * - categories: Categorías de productos
 *
 * Para modificar estas tablas, usar el sistema de migraciones.
 *
 * Tablas NO protegidas (pueden modificarse):
 * - logs: Registros de sistema
 * - cache: Datos temporales de caché
 * - sessions: Sesiones de usuario
 */
class ProductionORM extends VersaORM {
    protected $frozenTables = ['users', 'orders', 'products', 'categories'];
}
```

## Errores Comunes

### Error: Intentar Modificar Esquema en Producción

```php
// ❌ Error común: Agregar campos en producción
$user = VersaModel::load('users', 1);
$user->new_field = 'value'; // Fallará con Freeze Mode activo

// ✅ Solución: Usar migración
class AddNewFieldToUsers {
    public function up() {
        $user = $this->orm->dispense('users');
        $user->new_field = '';
        $this->orm->store($user);
        $this->orm->trash($user);
    }
}
```

### Error: No Manejar Excepciones de Freeze Mode

```php
// ❌ Error común: No capturar errores de Freeze Mode
$model->new_property = 'value';
$$model->store(); // Puede fallar sin manejo

// ✅ Solución: Manejar excepciones apropiadamente
try {
    $model->new_property = 'value';
    $$model->store();
} catch (VersaORMException $e) {
    if (strpos($e->getMessage(), 'Freeze Mode') !== false) {
        // Manejar error de esquema protegido
        $this->handleSchemaProtectionError($e);
    } else {
        throw $e;
    }
}
```

Freeze Mode es una herramienta esencial para mantener la estabilidad y seguridad de tu base de datos en producción, previniendo cambios accidentales que podrían comprometer la integridad de tu aplicación.

## Siguiente Paso

Continúa con la [Referencia SQL](../08-referencia-sql/README.md) para ver equivalencias completas entre SQL tradicional y VersaORM.
