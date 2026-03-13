# Transacciones

Las transacciones te permiten agrupar múltiples operaciones de base de datos en una uni, garantizando que todas se ejecuten correctamente o ninguna se aplique, manteniendo la integridad de los datos.

## Conceptos Clave

- **ACID**: Atomicidad, Consistencia, Aislamiento, Durabilidad
- **Atomicidad**: Todas las operaciones se ejecutan o ninguna
- **Rollback**: Revertir cambios en caso de error
- **Commit**: Confirmar y aplicar todos los cambios
- **Nested Transactions**: Transacciones anidadas (savepoints)

## Transacciones Básicas

### Ejemplo Básico

```php
<?php
require_once 'bootstrap.php';

try {
    // Iniciar transacción
    $orm->beginTransaction();

    // Operación 1: Crear usuario
    $userId = $orm->table('users')->insert([
        'name' => 'Juan Pérez',
        'email' => 'juan@example.com',
        'active' => true
    ]);

    // Operación 2: Crear perfil del usuario
    $profileId = $orm->table('user_profiles')->insert([
        'user_id' => $userId,
        'bio' => 'Desarrollador PHP',
        'website' => 'https://juan.dev'
    ]);

    // Operación 3: Asignar rol
    $orm->table('user_roles')->insert([
        'user_id' => $userId,
        'role' => 'developer'
    ]);

    // Si llegamos aquí, todo salió bien
    $orm->commit();
    echo "Usuario creado exitosamente con ID: $userId\n";

} catch (Exception $e) {
    // Si hay cualquier error, revertir todos los cambios
    $orm->rollback();
    echo "Error en la transacción: " . $e->getMessage() . "\n";
    echo "Todos los cambios han sido revertidos\n";
}
```

**SQL Equivalente:**
```sql
BEGIN;

INSERT INTO users (name, email, active) VALUES ('Juan Pérez', 'juan@example.com', 1);
INSERT INTO user_profiles (user_id, bio, website) VALUES (LAST_INSERT_ID(), 'Desarrollador PHP', 'https://juan.dev');
INSERT INTO user_roles (user_id, role) VALUES (LAST_INSERT_ID(), 'developer');

COMMIT;
-- O ROLLBACK; en caso de error
```

### Verificación de Estado de Transacción

```php
<?php
try {
    echo "Estado inicial: " . ($orm->inTransaction() ? "En transacción" : "Sin transacción") . "\n";

    $orm->beginTransaction();
    echo "Después de begin: " . ($orm->inTransaction() ? "En transacción" : "Sin transacción") . "\n";

    // Realizar operaciones...
    $orm->table('users')->insert(['name' => 'Test', 'email' => 'test@example.com']);

    $orm->commit();
    echo "Después de commit: " . ($orm->inTransaction() ? "En transacción" : "Sin transacción") . "\n";

} catch (Exception $e) {
    if ($orm->inTransaction()) {
        $orm->rollback();
        echo "Transacción revertida\n";
    }
}
```

## Transacciones con Operaciones Complejas

### Transferencia de Dinero (Ejemplo Clásico)

```php
<?php
function transferMoney($fromUserId, $toUserId, $amount) {
    $orm = VersaORM::getInstance();

    try {
        $orm->beginTransaction();

        // 1. Verificar saldo del usuario origen
        $fromUser = $orm->table('users')
            ->where('id', '=', $fromUserId)
            ->first();

        if (!$fromUser) {
            throw new Exception("Usuario origen no encontrado");
        }

        if ($fromUser['balance'] < $amount) {
            throw new Exception("Saldo insuficiente");
        }

        // 2. Verificar que el usuario destino existe
        $toUser = $orm->table('users')
            ->where('id', '=', $toUserId)
            ->first();

        if (!$toUser) {
            throw new Exception("Usuario destino no encontrado");
        }

        // 3. Debitar del usuario origen
        $orm->table('users')
            ->where('id', '=', $fromUserId)
            ->update(['balance' => $fromUser['balance'] - $amount]);

        // 4. Acreditar al usuario destino
        $orm->table('users')
            ->where('id', '=', $toUserId)
            ->update(['balance' => $toUser['balance'] + $amount]);

        // 5. Registrar la transacción
        $transactionId = $orm->table('transactions')->insert([
            'from_user_id' => $fromUserId,
            'to_user_id' => $toUserId,
            'amount' => $amount,
            'type' => 'transfer',
            'status' => 'completed',
            'created_at' => date('Y-m-d H:i:s')
        ]);

        // 6. Confirmar todos los cambios
        $orm->commit();

        return [
            'success' => true,
            'transaction_id' => $transactionId,
            'message' => "Transferencia de $$amount completada exitosamente"
        ];

    } catch (Exception $e) {
        $orm->rollback();

        return [
            'success' => false,
            'error' => $e->getMessage(),
            'message' => "La transferencia ha sido cancelada"
        ];
    }
}

// Uso de la función
$result = transferMoney(1, 2, 100.00);

if ($result['success']) {
    echo $result['message'] . "\n";
    echo "ID de transacción: " . $result['transaction_id'] . "\n";
} else {
    echo "Error: " . $result['error'] . "\n";
    echo $result['message'] . "\n";
}
```

### Procesamiento de Pedidos

```php
<?php
function processOrder($userId, $items) {
    $orm = VersaORM::getInstance();

    try {
        $orm->beginTransaction();

        $totalAmount = 0;
        $orderItems = [];

        // 1. Validar disponibilidad de productos y calcular total
        foreach ($items as $item) {
            $product = $orm->table('products')
                ->where('id', '=', $item['product_id'])
                ->first();

            if (!$product) {
                throw new Exception("Producto {$item['product_id']} no encontrado");
            }

            if ($product['stock'] < $item['quantity']) {
                throw new Exception("Stock insuficiente para {$product['name']}");
            }

            $itemTotal = $product['price'] * $item['quantity'];
            $totalAmount += $itemTotal;

            $orderItems[] = [
                'product_id' => $item['product_id'],
                'quantity' => $item['quantity'],
                'price' => $product['price'],
                'total' => $itemTotal
            ];
        }

        // 2. Crear el pedido
        $orderId = $orm->table('orders')->insert([
            'user_id' => $userId,
            'total_amount' => $totalAmount,
            'status' => 'processing',
            'created_at' => date('Y-m-d H:i:s')
        ]);

        // 3. Crear los items del pedido y actualizar stock
        foreach ($orderItems as $orderItem) {
            // Insertar item del pedido
            $orm->table('order_items')->insert([
                'order_id' => $orderId,
                'product_id' => $orderItem['product_id'],
                'quantity' => $orderItem['quantity'],
                'price' => $orderItem['price'],
                'total' => $orderItem['total']
            ]);

            // Reducir stock del producto
            $orm->table('products')
                ->where('id', '=', $orderItem['product_id'])
                ->decrement('stock', $orderItem['quantity']);
        }

        // 4. Registrar movimiento de inventario
        foreach ($orderItems as $orderItem) {
            $orm->table('inventory_movements')->insert([
                'product_id' => $orderItem['product_id'],
                'type' => 'sale',
                'quantity' => -$orderItem['quantity'],
                'reference_type' => 'order',
                'reference_id' => $orderId,
                'created_at' => date('Y-m-d H:i:s')
            ]);
        }

        // 5. Confirmar el pedido
        $orm->commit();

        return [
            'success' => true,
            'order_id' => $orderId,
            'total_amount' => $totalAmount,
            'items_count' => count($orderItems)
        ];

    } catch (Exception $e) {
        $orm->rollback();

        return [
            'success' => false,
            'error' => $e->getMessage()
        ];
    }
}

// Procesar un pedido
$orderData = [
    ['product_id' => 1, 'quantity' => 2],
    ['product_id' => 3, 'quantity' => 1],
    ['product_id' => 5, 'quantity' => 3]
];

$result = processOrder(1, $orderData);

if ($result['success']) {
    echo "Pedido procesado exitosamente\n";
    echo "ID del pedido: " . $result['order_id'] . "\n";
    echo "Total: $" . $result['total_amount'] . "\n";
    echo "Items: " . $result['items_count'] . "\n";
} else {
    echo "Error al procesar pedido: " . $result['error'] . "\n";
}
```

## Transacciones Anidadas (Savepoints)

### Ejemplo con Savepoints

```php
<?php
try {
    $orm->beginTransaction();
    echo "Transacción principal iniciada\n";

    // Operación 1: Crear usuario
    $userId = $orm->table('users')->insert([
        'name' => 'Usuario Principal',
        'email' => 'principal@example.com'
    ]);
    echo "Usuario creado: $userId\n";

    // Crear savepoint antes de operaciones riesgosas
    $orm->savepoint('before_profile');
    echo "Savepoint 'before_profile' creado\n";

    try {
        // Operación 2: Crear perfil (puede fallar)
        $profileId = $orm->table('user_profiles')->insert([
            'user_id' => $userId,
            'bio' => 'Bio del usuario',
            'invalid_field' => 'esto puede causar error' // Campo que no existe
        ]);
        echo "Perfil creado: $profileId\n";

    } catch (Exception $e) {
        // Rollback solo hasta el savepoint
        $orm->rollbackToSavepoint('before_profile');
        echo "Error en perfil, rollback a savepoint: " . $e->getMessage() . "\n";

        // Crear perfil con datos válidos
        $profileId = $orm->table('user_profiles')->insert([
            'user_id' => $userId,
            'bio' => 'Bio del usuario'
        ]);
        echo "Perfil creado correctamente: $profileId\n";
    }

    // Operación 3: Asignar rol
    $orm->table('user_roles')->insert([
        'user_id' => $userId,
        'role' => 'user'
    ]);
    echo "Rol asignado\n";

    // Confirmar toda la transacción
    $orm->commit();
    echo "Transacción principal confirmada\n";

} catch (Exception $e) {
    $orm->rollback();
    echo "Error en transacción principal: " . $e->getMessage() . "\n";
}
```

### Procesamiento por Lotes con Savepoints

```php
<?php
function processBatchWithSavepoints($dataArray, $batchSize = 100) {
    $orm = VersaORM::getInstance();
    $processed = 0;
    $errors = [];

    try {
        $orm->beginTransaction();

        $batches = array_chunk($dataArray, $batchSize);

        foreach ($batches as $batchIndex => $batch) {
            $savepointName = "batch_$batchIndex";
            $orm->savepoint($savepointName);

            try {
                // Procesar lote
                foreach ($batch as $item) {
                    $orm->table('processed_data')->insert($item);
                    $processed++;
                }

                echo "Lote $batchIndex procesado: " . count($batch) . " items\n";

            } catch (Exception $e) {
                // Rollback solo este lote
                $orm->rollbackToSavepoint($savepointName);
                $errors[] = [
                    'batch' => $batchIndex,
                    'error' => $e->getMessage()
                ];
                echo "Error en lote $batchIndex: " . $e->getMessage() . "\n";
            }
        }

        $orm->commit();

    } catch (Exception $e) {
        $orm->rollback();
        throw $e;
    }

    return [
        'processed' => $processed,
        'errors' => $errors
    ];
}
```

## Manejo de Deadlocks

### Detección y Reintento Automático

```php
<?php
function executeWithDeadlockRetry($operation, $maxRetries = 3) {
    $orm = VersaORM::getInstance();
    $attempt = 0;

    while ($attempt < $maxRetries) {
        try {
            $orm->beginTransaction();

            // Ejecutar la operación
            $result = $operation($orm);

            $orm->commit();
            return $result;

        } catch (VersaORMException $e) {
            $orm->rollback();

            // Verificar si es un deadlock
            if (strpos($e->getMessage(), 'Deadlock') !== false) {
                $attempt++;
                if ($attempt < $maxRetries) {
                    echo "Deadlock detectado, reintentando ($attempt/$maxRetries)...\n";
                    // Esperar un tiempo aleatorio antes de reintentar
                    usleep(rand(100000, 500000)); // 0.1 a 0.5 segundos
                    continue;
                }
            }

            // Si no es deadlock o se agotaron los reintentos
            throw $e;
        }
    }

    throw new Exception("Operación falló después de $maxRetries intentos");
}

// Uso del sistema anti-deadlock
$result = executeWithDeadlockRetry(function($orm) {
    // Operación que puede causar deadlock
    $orm->table('accounts')
        ->where('id', '=', 1)
        ->lockForUpdate()
        ->first();

    $orm->table('accounts')
        ->where('id', '=', 2)
        ->lockForUpdate()
        ->first();

    // Realizar transferencia...
    return "Transferencia completada";
});

echo $result . "\n";
```

## Transacciones de Solo Lectura

### Optimización para Consultas

```php
<?php
try {
    // Iniciar transacción de solo lectura
    $orm->beginTransaction(true); // true = solo lectura

    // Estas consultas tendrán una vista consistente de los datos
    $users = $orm->table('users')
        ->where('active', '=', true)
        ->getAll();

    $totalPosts = $orm->table('posts')
        ->whereIn('user_id', array_column($users, 'id'))
        ->count();

    $recentActivity = $orm->table('user_activity')
        ->where('created_at', '>', date('Y-m-d', strtotime('-7 days')))
        ->orderBy('created_at', 'DESC')
        ->limit(100)
        ->getAll();

    // Procesar datos sin riesgo de inconsistencias
    $report = [
        'active_users' => count($users),
        'total_posts' => $totalPosts,
        'recent_activities' => count($recentActivity)
    ];

    $orm->commit();

    echo "Reporte generado:\n";
    echo "- Usuarios activos: " . $report['active_users'] . "\n";
    echo "- Posts totales: " . $report['total_posts'] . "\n";
    echo "- Actividades recientes: " . $report['recent_activities'] . "\n";

} catch (Exception $e) {
    $orm->rollback();
    echo "Error generando reporte: " . $e->getMessage() . "\n";
}
```

## Monitoreo y Debugging

### Log de Transacciones

```php
<?php
class TransactionLogger {
    private $orm;
    private $startTime;
    private $operations;

    public function __construct($orm) {
        $this->orm = $orm;
        $this->operations = [];
    }

    public function begin($description = '') {
        $this->startTime = microtime(true);
        $this->operations = [];

        echo "[TRANSACTION] Iniciando: $description\n";
        $this->orm->beginTransaction();
    }

    public function logOperation($description, $table = null, $affected = null) {
        $this->operations[] = [
            'description' => $description,
            'table' => $table,
            'affected' => $affected,
            'time' => microtime(true) - $this->startTime
        ];

        echo "[OPERATION] $description" .
             ($table ? " en $table" : "") .
             ($affected ? " ($affected filas)" : "") . "\n";
    }

    public function commit() {
        $this->orm->commit();
        $totalTime = microtime(true) - $this->startTime;

        echo "[TRANSACTION] Confirmada en " . number_format($totalTime, 4) . "s\n";
        echo "[SUMMARY] " . count($this->operations) . " operaciones ejecutadas\n";

        foreach ($this->operations as $op) {
            echo "  - {$op['description']}: " . number_format($op['time'], 4) . "s\n";
        }
    }

    public function rollback($reason = '') {
        $this->orm->rollback();
        $totalTime = microtime(true) - $this->startTime;

        echo "[TRANSACTION] Revertida en " . number_format($totalTime, 4) . "s\n";
        echo "[REASON] $reason\n";
    }
}

// Uso del logger
$logger = new TransactionLogger($orm);

try {
    $logger->begin('Creación de usuario completo');

    $userId = $orm->table('users')->insert(['name' => 'Test', 'email' => 'test@example.com']);
    $logger->logOperation('Usuario insertado', 'users', 1);

    $profileId = $orm->table('user_profiles')->insert(['user_id' => $userId, 'bio' => 'Test bio']);
    $logger->logOperation('Perfil insertado', 'user_profiles', 1);

    $logger->commit();

} catch (Exception $e) {
    $logger->rollback($e->getMessage());
}
```

## Mejores Prácticas

### Estructura de Transacciones

```php
<?php
// ✅ Buena práctica: Transacciones cortas y específicas
function createUserWithProfile($userData, $profileData) {
    $orm = VersaORM::getInstance();

    try {
        $orm->beginTransaction();

        // Operaciones relacionadas y rápidas
        $userId = $orm->table('users')->insert($userData);
        $profileData['user_id'] = $userId;
        $profileId = $orm->table('user_profiles')->insert($profileData);

        $orm->commit();
        return ['user_id' => $userId, 'profile_id' => $profileId];

    } catch (Exception $e) {
        $orm->rollback();
        throw $e;
    }
}

// ❌ Mala práctica: Transacciones largas con operaciones no relacionadas
function badTransactionExample() {
    $orm = VersaORM::getInstance();

    try {
        $orm->beginTransaction();

        // Operación 1: Crear usuario
        $userId = $orm->table('users')->insert([...]);

        // Operación 2: Enviar email (lenta, no debería estar en transacción)
        sendWelcomeEmail($userId); // ❌ Operación externa lenta

        // Operación 3: Procesar imagen (lenta)
        processUserAvatar($userId); // ❌ Operación de archivo lenta

        // Operación 4: Llamada a API externa
        syncWithExternalService($userId); // ❌ Dependencia externa

        $orm->commit();

    } catch (Exception $e) {
        $orm->rollback();
        throw $e;
    }
}
```

### Manejo de Errores Específicos

```php
<?php
function robustTransactionExample() {
    $orm = VersaORM::getInstance();

    try {
        $orm->beginTransaction();

        // Operaciones de base de datos
        $result = performDatabaseOperations($orm);

        $orm->commit();

        // Operaciones post-commit (no críticas)
        try {
            sendNotifications($result);
            updateCache($result);
        } catch (Exception $e) {
            // Log pero no fallar la transacción ya confirmada
            error_log("Error post-commit: " . $e->getMessage());
        }

        return $result;

    } catch (VersaORMException $e) {
        $orm->rollback();

        // Manejo específico por tipo de error
        if (strpos($e->getMessage(), 'Duplicate entry') !== false) {
            throw new Exception("El registro ya existe");
        } elseif (strpos($e->getMessage(), 'foreign key constraint') !== false) {
            throw new Exception("Referencia inválida");
        } else {
            throw new Exception("Error de base de datos: " . $e->getMessage());
        }

    } catch (Exception $e) {
        $orm->rollback();
        throw $e;
    }
}
```

## Siguiente Paso

Ahora que dominas las transacciones, continúa con [Consultas Raw](consultas-raw.md) para aprender cuándo y cómo usar SQL directo en casos especiales.
