# Ejemplo Práctico: Modo Freeze y Creación Automática de Campos

## Introducción

Este ejemplo muestra cómo utilizar el **modo freeze** de VersaORM-PHP tanto para **proteger el esquema en producción** como para **desarrollar ágilmente** con creación automática de campos (estilo RedBeanPHP).

## Configuración Inicial

```php
<?php
require_once 'vendor/autoload.php';

use VersaORM\VersaORM;
use VersaORM\VersaModel;

$config = [
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_aplicacion',
    'username' => 'usuario',
    'password' => 'contraseña',
    'charset' => 'utf8mb4',
];

$orm = new VersaORM($config);
VersaModel::setORM($orm);

class Product extends VersaModel {
    protected string $table = 'products';
    protected array $fillable = ['*']; // Permitir todos los campos
}
```

## Escenario 1: Desarrollo Ágil (Freeze Desactivado)

### Creación Automática de Campos

```php
echo "=== MODO DESARROLLO (Freeze OFF) ===\n";

// Desactivar freeze para desarrollo ágil
$orm->freeze(false);
echo "Freeze status: " . ($orm->isFrozen() ? 'ON' : 'OFF') . "\n";

// Crear un producto con campos que NO existen en la tabla
$product = new Product('products', $orm);
$product->name = "Laptop Gaming";           // VARCHAR(255)
$product->price = 1299.99;                  // DECIMAL(10,2)
$product->stock = 15;                       // INT
$product->is_featured = true;               // BOOLEAN
$product->category = "Electronics";         // VARCHAR(255)
$product->specs = [                         // JSON
    'cpu' => 'Intel i7',
    'ram' => '16GB',
    'storage' => '512GB SSD'
];

echo "Guardando producto con campos nuevos...\n";
$product->store(); // ✅ Crea automáticamente todas las columnas
echo "✓ Producto guardado. Columnas creadas automáticamente.\n\n";

// Agregar más campos dinámicamente
$product2 = new Product('products', $orm);
$product2->name = "Mouse Inalámbrico";
$product2->price = 29.99;
$product2->warranty_months = 12;            // Nueva columna INT
$product2->supplier = "TechCorp";           // Nueva columna VARCHAR(255)
$product2->tags = ['wireless', 'ergonomic']; // Nueva columna JSON

$product2->store(); // ✅ Crea warranty_months, supplier, tags
echo "✓ Segundo producto guardado con campos adicionales.\n\n";
```

## Escenario 2: Producción Segura (Freeze Activado)

```php
<?php
// config/production.php

use VersaORM\VersaORM;
use VersaORM\VersaModel;

class ProductionBootstrap
{
    private VersaORM $orm;

    public function __construct()
    {
        $config = [
            'driver'   => 'mysql',
            'host'     => env('DB_HOST'),
            'port'     => env('DB_PORT', 3306),
            'database' => env('DB_DATABASE'),
            'username' => env('DB_USERNAME'),
            'password' => env('DB_PASSWORD'),
            'charset'  => 'utf8mb4',
            'debug'    => env('APP_DEBUG', false),
        ];

        $this->orm = new VersaORM($config);
        VersaModel::setORM($this->orm);

        // ACTIVAR FREEZE EN PRODUCCIÓN
        $this->setupProductionFreeze();
    }

    private function setupProductionFreeze(): void
    {
        // Activar freeze global para máxima protección
        $this->orm->freeze(true);

        // Log crítico para auditoría
        error_log('[SECURITY] Production freeze mode activated - DDL operations blocked');

        // Opcional: Proteger modelos específicos críticos
        $this->protectCriticalModels();
    }

    private function protectCriticalModels(): void
    {
        $criticalModels = [
            User::class,
            Payment::class,
            AuditLog::class,
            Permission::class,
        ];

        foreach ($criticalModels as $model) {
            $this->orm->freezeModel($model, true);
            error_log("[SECURITY] Model {$model} individually frozen");
        }
    }

    public function getORM(): VersaORM
    {
        return $this->orm;
    }
}
```

### 2. Middleware de Seguridad

```php
<?php
// middleware/FreezeSecurityMiddleware.php

class FreezeSecurityMiddleware
{
    private VersaORM $orm;

    public function __construct(VersaORM $orm)
    {
        $this->orm = $orm;
    }

    public function handle($request, $next)
    {
        // Verificar que el freeze esté activo en producción
        if (app()->environment('production') && !$this->orm->isFrozen()) {
            // ALERTA CRÍTICA: Freeze desactivado en producción
            $this->logSecurityAlert('FREEZE_DISABLED_IN_PRODUCTION');

            // Re-activar automáticamente
            $this->orm->freeze(true);
        }

        return $next($request);
    }

    private function logSecurityAlert(string $event): void
    {
        $alert = [
            'event' => $event,
            'severity' => 'CRITICAL',
            'timestamp' => now(),
            'ip' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'url' => request()->fullUrl(),
        ];

        // Log múltiple para redundancia
        error_log('[CRITICAL] ' . json_encode($alert));

        // Opcional: Enviar alerta por email/Slack
        // $this->sendSecurityAlert($alert);
    }
}
```

### 3. Servicio de Mantenimiento Controlado

```php
<?php
// services/MaintenanceService.php

class MaintenanceService
{
    private VersaORM $orm;
    private bool $originalFreezeState;

    public function __construct(VersaORM $orm)
    {
        $this->orm = $orm;
    }

    /**
     * Ejecutar mantenimiento que requiere DDL
     */
    public function executeMaintenance(callable $maintenanceTask): void
    {
        $this->enterMaintenanceMode();

        try {
            $maintenanceTask();
            $this->logMaintenanceSuccess();
        } catch (Exception $e) {
            $this->logMaintenanceError($e);
            throw $e;
        } finally {
            $this->exitMaintenanceMode();
        }
    }

    private function enterMaintenanceMode(): void
    {
        // Guardar estado actual
        $this->originalFreezeState = $this->orm->isFrozen();

        // Log del inicio de mantenimiento
        error_log('[MAINTENANCE] Entering maintenance mode - temporarily disabling freeze');

        // Desactivar freeze temporalmente
        $this->orm->freeze(false);

        // Notificar a stakeholders (opcional)
        // $this->notifyMaintenanceStart();
    }

    private function exitMaintenanceMode(): void
    {
        // Restaurar estado de freeze
        $this->orm->freeze($this->originalFreezeState);

        // Log del fin de mantenimiento
        $status = $this->originalFreezeState ? 'enabled' : 'disabled';
        error_log("[MAINTENANCE] Exiting maintenance mode - freeze {$status}");

        // Notificar a stakeholders (opcional)
        // $this->notifyMaintenanceEnd();
    }

    private function logMaintenanceSuccess(): void
    {
        error_log('[MAINTENANCE] Maintenance task completed successfully');
    }

    private function logMaintenanceError(Exception $e): void
    {
        error_log('[MAINTENANCE] Maintenance task failed: ' . $e->getMessage());
    }
}
```

### 4. Sistema de Migración Segura

```php
<?php
// commands/SecureMigrationCommand.php

class SecureMigrationCommand
{
    private VersaORM $orm;
    private MaintenanceService $maintenance;

    public function __construct(VersaORM $orm, MaintenanceService $maintenance)
    {
        $this->orm = $orm;
        $this->maintenance = $maintenance;
    }

    public function runMigrations(): void
    {
        // Verificar permisos antes de proceder
        $this->verifyMigrationPermissions();

        // Ejecutar migraciones en modo mantenimiento
        $this->maintenance->executeMaintenance(function() {
            $this->executeMigrations();
        });
    }

    private function verifyMigrationPermissions(): void
    {
        // Solo permitir migraciones en entornos autorizados
        $allowedEnvironments = ['local', 'staging'];
        $currentEnv = app()->environment();

        if (!in_array($currentEnv, $allowedEnvironments)) {
            throw new SecurityException(
                "Migrations not allowed in {$currentEnv} environment. " .
                "Use maintenance service for production changes."
            );
        }
    }

    private function executeMigrations(): void
    {
        try {
            // Crear tabla de ejemplo
            $this->orm->exec("
                CREATE TABLE IF NOT EXISTS migration_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    migration VARCHAR(255) NOT NULL,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ");

            echo "✅ Migration completed successfully\n";

        } catch (VersaORMException $e) {
            if ($e->getCode() === 'FREEZE_VIOLATION') {
                echo "❌ Migration blocked by freeze mode\n";
                echo "Use MaintenanceService::executeMaintenance() for DDL operations\n";
            }
            throw $e;
        }
    }
}
```

### 5. Dashboard de Monitoreo

```php
<?php
// controllers/SecurityDashboard.php

class SecurityDashboard
{
    private VersaORM $orm;

    public function __construct(VersaORM $orm)
    {
        $this->orm = $orm;
    }

    public function getSecurityStatus(): array
    {
        return [
            'freeze_status' => $this->getFreezeStatus(),
            'recent_violations' => $this->getRecentViolations(),
            'system_health' => $this->getSystemHealth(),
        ];
    }

    private function getFreezeStatus(): array
    {
        return [
            'global_freeze' => $this->orm->isFrozen(),
            'protected_models' => $this->getProtectedModels(),
            'last_freeze_change' => $this->getLastFreezeChange(),
        ];
    }

    private function getProtectedModels(): array
    {
        $models = [User::class, Payment::class, AuditLog::class];
        $status = [];

        foreach ($models as $model) {
            $status[$model] = $this->orm->isModelFrozen($model);
        }

        return $status;
    }

    private function getRecentViolations(): array
    {
        // Leer logs de seguridad de los últimos 7 días
        $logPath = storage_path('logs/security-' . date('Y-m-d') . '.log');

        if (!file_exists($logPath)) {
            return [];
        }

        $content = file_get_contents($logPath);
        $violations = [];

        // Buscar intentos de violación
        if (preg_match_all('/FREEZE_VIOLATION_ATTEMPT.*/', $content, $matches)) {
            foreach ($matches[0] as $match) {
                $violations[] = $this->parseLogEntry($match);
            }
        }

        return array_slice($violations, -10); // Últimas 10 violaciones
    }

    private function parseLogEntry(string $logEntry): array
    {
        // Parsear entrada de log y extraer información relevante
        return [
            'timestamp' => $this->extractTimestamp($logEntry),
            'operation' => $this->extractOperation($logEntry),
            'blocked' => true,
            'severity' => 'HIGH',
        ];
    }

    private function getSystemHealth(): array
    {
        return [
            'database_connected' => $this->isDatabaseConnected(),
            'freeze_functional' => $this->isFreezeSystemFunctional(),
            'logs_writable' => $this->areLogsWritable(),
        ];
    }

    private function isDatabaseConnected(): bool
    {
        try {
            $this->orm->table('information_schema.tables')->limit(1)->get();
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    private function isFreezeSystemFunctional(): bool
    {
        try {
            // Test básico de funcionalidad freeze
            $originalState = $this->orm->isFrozen();
            $this->orm->freeze(!$originalState);
            $newState = $this->orm->isFrozen();
            $this->orm->freeze($originalState); // Restaurar

            return $newState !== $originalState;
        } catch (Exception $e) {
            return false;
        }
    }

    private function areLogsWritable(): bool
    {
        $logPath = storage_path('logs/');
        return is_writable($logPath);
    }
}
```

## Uso en Templates

### Vista del Dashboard

```html
<!-- resources/views/security/dashboard.blade.php -->
<div class="security-dashboard">
    <h2>🔒 Security Status</h2>

    <div class="freeze-status">
        <h3>Freeze Mode Status</h3>
        <div class="status-indicator {{ $status['freeze_status']['global_freeze'] ? 'active' : 'inactive' }}">
            Global Freeze: {{ $status['freeze_status']['global_freeze'] ? '🔒 ACTIVE' : '🔓 INACTIVE' }}
        </div>

        <h4>Protected Models:</h4>
        <ul>
            @foreach($status['freeze_status']['protected_models'] as $model => $protected)
                <li class="{{ $protected ? 'protected' : 'unprotected' }}">
                    {{ $model }}: {{ $protected ? '🛡️ Protected' : '⚠️ Unprotected' }}
                </li>
            @endforeach
        </ul>
    </div>

    <div class="recent-violations">
        <h3>Recent Security Violations</h3>
        @if(empty($status['recent_violations']))
            <p class="no-violations">✅ No recent violations detected</p>
        @else
            <ul>
                @foreach($status['recent_violations'] as $violation)
                    <li class="violation">
                        <strong>{{ $violation['timestamp'] }}</strong>:
                        {{ $violation['operation'] }} -
                        <span class="severity-{{ strtolower($violation['severity']) }}">
                            {{ $violation['severity'] }}
                        </span>
                    </li>
                @endforeach
            </ul>
        @endif
    </div>
</div>

<style>
.status-indicator.active { color: green; font-weight: bold; }
.status-indicator.inactive { color: orange; font-weight: bold; }
.protected { color: green; }
.unprotected { color: orange; }
.severity-high { color: red; font-weight: bold; }
.no-violations { color: green; }
</style>
```

## Resultados Esperados

Con esta implementación obtienes:

1. **🔒 Protección Automática**: El freeze se activa automáticamente en producción
2. **📊 Monitoreo Continuo**: Dashboard en tiempo real del estado de seguridad
3. **🛠️ Mantenimiento Controlado**: Proceso seguro para operaciones DDL necesarias
4. **📝 Auditoría Completa**: Logs detallados de todos los eventos de seguridad
5. **⚡ Respuesta Automática**: Re-activación automática si el freeze se desactiva

## Logs de Ejemplo

```log
[2025-08-05 15:30:45] [SECURITY] Production freeze mode activated - DDL operations blocked
[2025-08-05 15:30:45] [SECURITY] Model User individually frozen
[2025-08-05 15:30:45] [SECURITY] Model Payment individually frozen
[2025-08-05 16:45:12] [CRITICAL] FREEZE_VIOLATION_ATTEMPT: operation=CREATE_TABLE, blocked=true
[2025-08-05 18:20:33] [MAINTENANCE] Entering maintenance mode - temporarily disabling freeze
[2025-08-05 18:25:17] [MAINTENANCE] Maintenance task completed successfully
[2025-08-05 18:25:17] [MAINTENANCE] Exiting maintenance mode - freeze enabled
```

Este ejemplo demuestra una implementación robusta y completa del modo freeze en un entorno de producción real, proporcionando múltiples capas de protección y monitoreo continuo.
