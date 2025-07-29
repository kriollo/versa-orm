# Ejemplos Avanzados de VersaORM

Esta guía proporciona ejemplos avanzados de uso de VersaORM en contextos más complejos.

## Tabla de Contenidos

- [Transacciones Complejas](#transacciones-complejas)
- [Consultas Personalizadas y Raw](#consultas-personalizadas-y-raw)
- [Optimización de Consultas](#optimización-de-consultas)
- [Manipulación de Datos Complejos](#manipulación-de-datos-complejos)
- [Integración con Servicios Externos](#integración-con-servicios-externos)

---

## Transacciones Complejas

### Uso de Transacciones

```php
function performTransaction($orm) {
    try {
        $orm->exec('START TRANSACTION');

        // Operación 1
        $user = $orm->dispense('users');
        $user->name = 'Nuevo Usuario';
        $orm->store($user);

        // Operación 2
        $order = $orm->dispense('orders');
        $order->user_id = $user->id;
        $order->total = 150.00;
        $orm->store($order);

        $orm->exec('COMMIT');
        echo "Transacción completada con éxito.";
        return true;

    } catch (Exception $e) {
        $orm->exec('ROLLBACK');
        echo "Error en transacción: " . $e->getMessage();
        return false;
    }
}
```

### Gestión de Errores en Transacciones

```php
function safeTransfer($orm, $fromAccountId, $toAccountId, $amount) {
    try {
        $orm->exec('START TRANSACTION');

        // Debitar
        $fromAccount = $orm->findOne('accounts', $fromAccountId);
        if ($fromAccount->balance < $amount) {
            throw new Exception('Saldo insuficiente');
        }
        $fromAccount->balance -= $amount;
        $orm->store($fromAccount);

        // Acreditar
        $toAccount = $orm->findOne('accounts', $toAccountId);
        $toAccount->balance += $amount;
        $orm->store($toAccount);

        $orm->exec('COMMIT');
        echo "Transferencia completada.";

    } catch (Exception $e) {
        $orm->exec('ROLLBACK');
        echo "Error en transferencia: " . $e->getMessage();
    }
}
```

---

## Consultas Personalizadas y Raw

### Uso Avanzado de Consultas Raw

```php
function fetchUserAnalytics($orm) {
    return $orm->exec('
        SELECT 
            u.id, 
            u.name, 
            COUNT(o.id) as order_count,
            SUM(o.total) as total_spent
        FROM users u
        JOIN orders o ON u.id = o.user_id
        WHERE o.status = "completed"
        GROUP BY u.id, u.name
        HAVING order_count > 5
        ORDER BY total_spent DESC
    ');
}
```

### Consultas Dinámicas

```php
function dynamicQuery($orm, $filters) {
    $query = $orm->table('products');

    if (!empty($filters['category'])) {
        $query->where('category', '=', $filters['category']);
    }

    if (!empty($filters['price_min'])) {
        $query->where('price', '>=', $filters['price_min']);
    }

    if (!empty($filters['price_max'])) {
        $query->where('price', '<=', $filters['price_max']);
    }

    return $query->getAll();
}
```

---

## Optimización de Consultas

### Uso Eficiente de Índices

```php
function optimizedSearch($orm) {
    return $orm->table('products')
        ->where('stock', '>', 10)
        ->where('category', '=', 'electronics')
        ->orderBy('price', 'asc')
        ->limit(100)
        ->getAll();
}
```

### Prefetching Datos Relacionados

```php
function prefetchData($orm) {
    $orders = $orm->table('orders')
        ->select(['orders.*', 'users.name as user_name'])
        ->join('users', 'orders.user_id', '=', 'users.id')
        ->getAll();
    
    foreach ($orders as $order) {
        echo "Orden ID: {$order['id']} - Usuario: {$order['user_name']}\n";
    }
}
```

---

## Manipulación de Datos Complejos

### Agrupación y Agregación

```php
function salesOverview($orm) {
    return $orm->table('sales')
        ->select(['MONTH(created_at) as month', 'SUM(amount) as total_sales'])
        ->groupBy('month')
        ->orderBy('month', 'asc')
        ->getAll();
}
```

### Procesamiento Batch

```php
function batchUpdate($orm) {
    $orm->exec('
        UPDATE users SET status = "inactive" 
        WHERE last_login < NOW() - INTERVAL 1 YEAR
    ');
    echo "Usuarios inactivos actualizados.";
}
```

---

## Integración con Servicios Externos

### Sincronización de Datos con API

```php
function syncWithExternalService($orm, $externalService) {
    $products = $orm->table('products')->getAll();
    foreach ($products as $product) {
        // Lógica para sincronizar con API externa
        $externalService->updateProduct($product['id'], [
            'name' => $product['name'],
            'price' => $product['price'],
            'stock' => $product['stock'],
        ]);
    }
    echo "Sincronización completada.";
}
```

### Planificación de Tareas

```php
function scheduleTasks($taskManager, $orm) {
    $overdueTasks = $orm->table('tasks')
        ->where('due_date', '<', date('Y-m-d'))
        ->where('status', '!=', 'completed')
        ->getAll();
    
    foreach ($overdueTasks as $task) {
        $taskManager->notifyOwner($task['id']);
        echo "Notificación enviada para la tarea ID {task['id']}";
    }
}
```

---

Estos ejemplos avanzados muestran cómo usar VersaORM para manejar escenarios complejos y optimizar el rendimiento de la aplicación. Aprovecha la flexibilidad del ORM para crear soluciones adaptadas a tus necesidades específicas.
