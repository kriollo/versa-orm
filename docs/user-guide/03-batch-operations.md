# 🚀 Operaciones de Lote (Batch Operations) - Guía Completa

¡Bienvenido a la documentación de las Operaciones de Lote de VersaORM! Esta funcionalidad revoluciona la forma en que manejas grandes volúmenes de datos con máximo rendimiento y seguridad.

## 🎯 ¿Qué son las Operaciones de Lote?

Las **Operaciones de Lote** te permiten realizar operaciones masivas de inserción, actualización y eliminación de datos de manera ultra-optimizada, procesando cientos o miles de registros en una sola operación.

### 🔥 Ventajas Clave

| Operación Tradicional | Operación de Lote |
|----------------------|-------------------|
| 1000 INSERT individuales = 1000 consultas | 1000 registros = 1 consulta optimizada |
| Tiempo: ~10 segundos | Tiempo: ~0.5 segundos |
| Uso de memoria: Alto | Uso de memoria: Optimizado |
| Transacciones: Inconsistente | Transacciones: Atómica por lote |

---

## 🔧 Operaciones Disponibles

### 1. **insertMany()** - Inserción Masiva Optimizada

Inserta múltiples registros usando la sintaxis SQL más eficiente: `INSERT INTO table (cols) VALUES (val1), (val2), ...`

#### Ejemplo SQL vs VersaORM
```sql
-- SQL
INSERT INTO users (name, email, status) VALUES
('Juan Pérez', 'juan@example.com', 'active'),
('María García', 'maria@example.com', 'active'),
('Carlos López', 'carlos@example.com', 'inactive');
```

```php
// VersaORM
$users = [
    ['name' => 'Juan Pérez', 'email' => 'juan@example.com', 'status' => 'active'],
    ['name' => 'María García', 'email' => 'maria@example.com', 'status' => 'active'],
    ['name' => 'Carlos López', 'email' => 'carlos@example.com', 'status' => 'inactive'],
];

$result = $orm->table('users')->insertMany($users, 1000);
```

### Sintaxis Básica
```php
$result = $orm->table('users')->insertMany($records, $batchSize);
```

#### Ejemplo Práctico
```php
$users = [
    ['name' => 'Juan Pérez', 'email' => 'juan@example.com', 'status' => 'active'],
    ['name' => 'María García', 'email' => 'maria@example.com', 'status' => 'active'],
    ['name' => 'Carlos López', 'email' => 'carlos@example.com', 'status' => 'inactive'],
    // ... hasta 10,000 registros
];

$result = $orm->table('users')->insertMany($users, 1000);

// Resultado:
// [
//     'total_inserted' => 3,
//     'batches_processed' => 1,
//     'batch_size' => 1000,
//     'status' => 'success',
//     'errors' => []
// ]
```

#### Parámetros Avanzados
```php
// Inserción con lotes más pequeños para control granular
$result = $orm->table('products')->insertMany($products, 500);

// Máximo batch_size permitido: 10,000
// Mínimo batch_size permitido: 1
```

#### Ejemplo SQL vs VersaORM
```sql
-- SQL
UPDATE users SET status = 'active', updated_at = '2024-01-01 10:30:00'
WHERE status = 'inactive' AND created_at > '2024-01-01';
```

```php
// VersaORM
$result = $orm->table('users')
    ->where('status', '=', 'inactive')
    ->where('created_at', '>', '2024-01-01')
    ->updateMany([
        'status' => 'active',
        'updated_at' => date('Y-m-d H:i:s')
    ], 5000); // Máximo 5000 registros
```

### 2. **updateMany()** - Actualización Masiva Segura

Actualiza múltiples registros que coincidan con condiciones WHERE específicas, con límites de seguridad incorporados.

#### Sintaxis Básica
```php
$result = $orm->table('users')
    ->where('status', '=', 'inactive')
    ->updateMany($data, $maxRecords);
```

#### Ejemplo Práctico
```php
// Activar todos los usuarios inactivos
$result = $orm->table('users')
    ->where('status', '=', 'inactive')
    ->where('created_at', '>', '2024-01-01')
    ->updateMany([
        'status' => 'active',
        'updated_at' => date('Y-m-d H:i:s')
    ], 5000); // Máximo 5000 registros

// Resultado:
// [
//     'rows_affected' => 1250,
//     'expected_count' => 1250,
//     'status' => 'success',
//     'update_data' => ['status' => 'active', 'updated_at' => '2024-01-01 10:30:00']
// ]
```

#### Características de Seguridad
- **Requiere condiciones WHERE** para prevenir actualizaciones accidentales masivas
- **Límite máximo de registros** configurable por seguridad
- **Conteo previo** para verificar cuántos registros serán afectados

#### Ejemplo SQL vs VersaORM
```sql
-- SQL
DELETE FROM application_logs
WHERE level = 'debug' AND created_at < '2023-01-01';
```

```php
// VersaORM
$result = $orm->table('application_logs')
    ->where('level', '=', 'debug')
    ->where('created_at', '<', date('Y-m-d', strtotime('-30 days')))
    ->deleteMany(10000); // Máximo 10,000 registros
```

### 3. **deleteMany()** - Eliminación Masiva Controlada

Elimina múltiples registros con las mismas garantías de seguridad que `updateMany()`.

#### Sintaxis Básica
```php
$result = $orm->table('logs')
    ->where('created_at', '<', '2023-01-01')
    ->deleteMany($maxRecords);
```

#### Ejemplo Práctico
```php
// Limpiar logs antiguos
$result = $orm->table('application_logs')
    ->where('level', '=', 'debug')
    ->where('created_at', '<', date('Y-m-d', strtotime('-30 days')))
    ->deleteMany(10000); // Máximo 10,000 registros

// Resultado:
// [
//     'rows_affected' => 8750,
//     'expected_count' => 8750,
//     'status' => 'success'
// ]
```

#### Protecciones Incorporadas
- **Condiciones WHERE obligatorias** para prevenir eliminaciones accidentales
- **Límite de seguridad** para operaciones masivas
- **Verificación previa** del número de registros a eliminar

#### Ejemplo SQL vs VersaORM
```sql
-- SQL (MySQL)
INSERT INTO products (sku, name, price, stock) VALUES
('PROD001', 'Laptop Pro', 1500.00, 10),
('PROD002', 'Mouse Inalámbrico', 25.99, 50),
('PROD003', 'Teclado Mecánico', 89.99, 30)
ON DUPLICATE KEY UPDATE name=VALUES(name), price=VALUES(price), stock=VALUES(stock);
```

```php
// VersaORM
$products = [
    ['sku' => 'PROD001', 'name' => 'Laptop Pro', 'price' => 1500.00, 'stock' => 10],
    ['sku' => 'PROD002', 'name' => 'Mouse Inalámbrico', 'price' => 25.99, 'stock' => 50],
    ['sku' => 'PROD003', 'name' => 'Teclado Mecánico', 'price' => 89.99, 'stock' => 30]
];

$result = $orm->table('products')->upsertMany(
    $products,
    ['sku'], // Clave única para detectar duplicados
    ['name', 'price', 'stock'], // Columnas a actualizar si existe
    1000 // Tamaño de lote
);
```

### 4. **upsertMany()** - Inserción/Actualización Inteligente

Combina INSERT y UPDATE en una sola operación. Inserta registros nuevos y actualiza los existentes basado en claves únicas.

#### Sintaxis Básica
```php
$result = $orm->table('products')->upsertMany(
    $records,
    $uniqueKeys,
    $updateColumns,
    $batchSize
);
```

#### Ejemplo Práctico
```php
$products = [
    ['sku' => 'PROD001', 'name' => 'Laptop Pro', 'price' => 1500.00, 'stock' => 10],
    ['sku' => 'PROD002', 'name' => 'Mouse Inalámbrico', 'price' => 25.99, 'stock' => 50],
    ['sku' => 'PROD003', 'name' => 'Teclado Mecánico', 'price' => 89.99, 'stock' => 30]
];

$result = $orm->table('products')->upsertMany(
    $products,
    ['sku'], // Clave única para detectar duplicados
    ['name', 'price', 'stock'], // Columnas a actualizar si existe
    1000 // Tamaño de lote
);

// Resultado:
// [
//     'total_processed' => 3,
//     'batches_processed' => 1,
//     'unique_keys' => ['sku'],
//     'update_columns' => ['name', 'price', 'stock'],
//     'status' => 'success'
// ]
```

#### Compatibilidad por Base de Datos
- **MySQL**: Usa `INSERT ... ON DUPLICATE KEY UPDATE`
- **PostgreSQL**: Usa `INSERT ... ON CONFLICT DO UPDATE`
- **SQLite**: No soportado actualmente

### 5. **replaceIntoMany()** - Reemplazo Masivo para MySQL

⚠️ **Solo MySQL**: Reemplaza completamente registros existentes o inserta nuevos. **ADVERTENCIA**: Puede perder datos de columnas no especificadas.

#### Ejemplo SQL vs VersaORM
```sql
-- SQL (MySQL)
REPLACE INTO products (sku, name, price) VALUES
('PROD001', 'Laptop Pro Updated', 1600.00),
('PROD002', 'Mouse Gaming', 35.99),
('PROD004', 'Monitor 4K', 299.99);
```

```php
// VersaORM
$products = [
    ['sku' => 'PROD001', 'name' => 'Laptop Pro Updated', 'price' => 1600.00],
    ['sku' => 'PROD002', 'name' => 'Mouse Gaming', 'price' => 35.99],
    ['sku' => 'PROD004', 'name' => 'Monitor 4K', 'price' => 299.99]
];

$result = $orm->table('products')->replaceIntoMany($products, 1000);
```

#### Sintaxis Básica
```php
$result = $orm->table('products')->replaceIntoMany($records, $batchSize);
```

#### Diferencia con upsertMany()
```php
// REPLACE INTO - Reemplaza COMPLETAMENTE el registro
// Si el producto existe con columnas 'description' y 'category', 
// estas se perderán si no se incluyen en los datos nuevos
$replaceResult = $orm->table('products')->replaceIntoMany([
    ['sku' => 'PROD001', 'name' => 'New Name', 'price' => 100]
    // description y category se establecerán como NULL
]);

// UPSERT - Solo actualiza las columnas especificadas
// Preserva las columnas existentes que no se especifican
$upsertResult = $orm->table('products')->upsertMany(
    [['sku' => 'PROD001', 'name' => 'New Name', 'price' => 100]],
    ['sku'],
    ['name', 'price'] // Solo actualiza name y price, preserva description y category
);
```

---

## 🛡️ Características de Seguridad

### Validación Estricta de Estructura
```php
// ❌ ESTO FALLARÁ - Estructura inconsistente
$records = [
    ['name' => 'User 1', 'email' => 'user1@example.com'],
    ['name' => 'User 2', 'email' => 'user2@example.com', 'extra_field' => 'data'] // Campo extra
];

// ✅ ESTO FUNCIONARÁ - Estructura consistente
$records = [
    ['name' => 'User 1', 'email' => 'user1@example.com', 'status' => 'active'],
    ['name' => 'User 2', 'email' => 'user2@example.com', 'status' => 'inactive']
];
```

### Protección contra Inyección SQL
```php
// ❌ ESTO SERÁ RECHAZADO - Nombre de columna malicioso
$records = [
    ['name; DROP TABLE users; --' => 'Malicious', 'email' => 'hack@example.com']
];
// VersaORMException: Invalid or malicious column name detected

// ✅ ESTO ES SEGURO - Nombres válidos
$records = [
    ['user_name' => 'Valid User', 'email_address' => 'valid@example.com']
];
```

### Límites de Seguridad Configurables
```php
// Configurar límites personalizados
$result = $orm->table('users')
    ->where('status', '=', 'pending')
    ->updateMany(['status' => 'processed'], 50000); // Límite personalizado

// Límites por defecto:
// - insertMany: batch_size máximo 10,000
// - updateMany/deleteMany: max_records máximo 100,000
```

---

## ⚡ Optimización de Rendimiento

### Mejores Prácticas para Lotes Grandes

#### 1. Tamaño de Lote Óptimo
```php
// Para datasets pequeños (< 1000 registros)
$batchSize = 500;

// Para datasets medianos (1000-10000 registros)  
$batchSize = 1000;

// Para datasets grandes (> 10000 registros)
$batchSize = 2000;

$result = $orm->table('logs')->insertMany($records, $batchSize);
```

#### 2. Procesamiento en Chunks
```php
$allRecords = range(1, 50000); // 50,000 registros
$chunkSize = 5000;

foreach (array_chunk($allRecords, $chunkSize) as $chunk) {
    $records = array_map(function($i) {
        return [
            'name' => "User {$i}",
            'email' => "user{$i}@example.com",
            'created_at' => date('Y-m-d H:i:s')
        ];
    }, $chunk);
    
    $result = $orm->table('users')->insertMany($records, 1000);
    echo "Processed chunk: {$result['total_inserted']} records\n";
}
```

#### 3. Monitoreo de Rendimiento
```php
$startTime = microtime(true);

$result = $orm->table('products')->insertMany($products, 1000);

$endTime = microtime(true);
$executionTime = $endTime - $startTime;

echo "Inserted {$result['total_inserted']} records in {$executionTime:.2f} seconds\n";
echo "Rate: " . round($result['total_inserted'] / $executionTime) . " records/second\n";
```

---

## 🚨 Manejo de Errores

### Tipos de Errores y Soluciones

#### 1. Errores de Validación
```php
try {
    $result = $orm->table('users')->insertMany([]);
} catch (VersaORMException $e) {
    if (strpos($e->getMessage(), 'at least one record') !== false) {
        echo "Error: Se requiere al menos un registro para insertar\n";
    }
}
```

#### 2. Errores de Estructura
```php
try {
    $records = [
        ['name' => 'User 1', 'email' => 'user1@example.com'],
        ['name' => 'User 2'] // Falta campo email
    ];
    
    $result = $orm->table('users')->insertMany($records);
} catch (VersaORMException $e) {
    if (strpos($e->getMessage(), 'different columns') !== false) {
        echo "Error: Todos los registros deben tener la misma estructura\n";
    }
}
```

#### 3. Errores de Límites de Seguridad
```php
try {
    $result = $orm->table('users')
        ->where('status', '=', 'all') // Esto podría afectar muchos registros
        ->updateMany(['status' => 'updated'], 100); // Límite bajo
} catch (Exception $e) {
    if (strpos($e->getMessage(), 'exceeds the maximum limit') !== false) {
        echo "Error: La operación excede el límite de seguridad\n";
        echo "Usa condiciones WHERE más restrictivas o aumenta max_records\n";
    }
}
```

### Recuperación de Errores
```php
function safeInsertMany($orm, $table, $records, $batchSize = 1000) {
    $totalInserted = 0;
    $errors = [];
    
    // Procesar en chunks para manejar errores por lote
    foreach (array_chunk($records, $batchSize) as $index => $chunk) {
        try {
            $result = $orm->table($table)->insertMany($chunk, $batchSize);
            $totalInserted += $result['total_inserted'];
            echo "Chunk {$index}: {$result['total_inserted']} records inserted\n";
        } catch (Exception $e) {
            $errors[] = "Chunk {$index} failed: " . $e->getMessage();
            echo "Chunk {$index} failed, continuing with next chunk...\n";
        }
    }
    
    return [
        'total_inserted' => $totalInserted,
        'errors' => $errors,
        'success_rate' => $totalInserted / count($records) * 100
    ];
}
```

---

## 📊 Casos de Uso Comunes

### 1. Migración de Datos
```php
// Migrar usuarios desde un sistema legacy
function migrateUsersFromLegacy($legacyData) {
    $users = [];
    
    foreach ($legacyData as $legacy) {
        $users[] = [
            'name' => $legacy['full_name'],
            'email' => strtolower($legacy['email_addr']),
            'status' => $legacy['is_active'] ? 'active' : 'inactive',
            'created_at' => $legacy['registration_date'],
            'migrated_from' => 'legacy_system_v1'
        ];
    }
    
    return $orm->table('users')->insertMany($users, 2000);
}
```

### 2. Procesamiento de Logs
```php
// Procesar y limpiar logs antiguos
function cleanupOldLogs($orm, $retentionDays = 30) {
    $cutoffDate = date('Y-m-d', strtotime("-{$retentionDays} days"));
    
    // Primero, archivar logs importantes
    $importantLogs = $orm->table('application_logs')
        ->where('level', 'IN', ['error', 'critical'])
        ->where('created_at', '<', $cutoffDate)
        ->get();
    
    if (!empty($importantLogs)) {
        $orm->table('archived_logs')->insertMany($importantLogs, 1000);
    }
    
    // Luego, eliminar logs antiguos
    return $orm->table('application_logs')
        ->where('created_at', '<', $cutoffDate)
        ->deleteMany(50000);
}
```

### 3. Actualización Masiva de Precios
```php
// Aplicar descuento masivo a productos
function applyMassSaleDiscount($orm, $categoryId, $discountPercent) {
    // Validar que no vamos a afectar demasiados productos
    $affectedCount = $orm->table('products')
        ->where('category_id', '=', $categoryId)
        ->where('is_active', '=', true)
        ->count();
    
    if ($affectedCount > 10000) {
        throw new Exception("Too many products would be affected: {$affectedCount}");
    }
    
    return $orm->table('products')
        ->where('category_id', '=', $categoryId)
        ->where('is_active', '=', true)
        ->updateMany([
            'sale_price' => 'price * ' . (1 - $discountPercent / 100),
            'on_sale' => true,
            'sale_updated_at' => date('Y-m-d H:i:s')
        ], 15000);
}
```

### 4. Sincronización de Inventario
```php
// Sincronizar inventario desde API externa
function syncInventoryFromAPI($orm, $apiData) {
    $products = [];
    
    foreach ($apiData as $item) {
        $products[] = [
            'sku' => $item['product_code'],
            'name' => $item['product_name'],
            'price' => $item['unit_price'],
            'stock' => $item['available_quantity'],
            'updated_at' => date('Y-m-d H:i:s')
        ];
    }
    
    // Usar upsert para actualizar existentes e insertar nuevos
    return $orm->table('products')->upsertMany(
        $products,
        ['sku'], // Clave única
        ['name', 'price', 'stock', 'updated_at'], // Columnas a actualizar
        1500 // Tamaño de lote
    );
}
```

---

## 🔍 Debugging y Monitoring

### Habilitando Debug Mode
```php
// Habilitar debug para ver las consultas SQL generadas
$config['debug'] = true;
$orm = new VersaORM($config);

$result = $orm->table('users')->insertMany($records, 500);
// Las consultas SQL se registrarán en logs/YYYY-MM-DD.log
```

### Métricas de Rendimiento
```php
function benchmarkBatchOperation($orm, $operation, $records) {
    $metrics = [
        'start_time' => microtime(true),
        'memory_start' => memory_get_usage(true),
        'peak_memory' => 0,
        'sql_queries' => 0
    ];
    
    try {
        $result = $operation($orm, $records);
        
        $metrics['end_time'] = microtime(true);
        $metrics['memory_end'] = memory_get_usage(true);
        $metrics['peak_memory'] = memory_get_peak_usage(true);
        $metrics['execution_time'] = $metrics['end_time'] - $metrics['start_time'];
        $metrics['memory_used'] = $metrics['memory_end'] - $metrics['memory_start'];
        $metrics['records_per_second'] = count($records) / $metrics['execution_time'];
        
        return array_merge($result, ['metrics' => $metrics]);
        
    } catch (Exception $e) {
        $metrics['error'] = $e->getMessage();
        return ['status' => 'error', 'metrics' => $metrics];
    }
}

// Uso
$benchmark = benchmarkBatchOperation($orm, function($orm, $records) {
    return $orm->table('users')->insertMany($records, 1000);
}, $userRecords);

echo "Performance: {$benchmark['metrics']['records_per_second']:.0f} records/second\n";
```

---

## 🎓 Resumen de Mejores Prácticas

### ✅ Qué SÍ hacer:
- Usar lotes de 1000-2000 registros para balance óptimo
- Validar estructura de datos antes de operaciones masivas
- Implementar manejo de errores robusto con recuperación
- Monitorear rendimiento y memoria en operaciones grandes
- Usar condiciones WHERE específicas en updateMany/deleteMany
- Procesar datos en chunks para datasets muy grandes

### ❌ Qué NO hacer:
- Nunca usar updateMany/deleteMany sin condiciones WHERE
- No procesar más de 10,000 registros por lote
- No ignorar los límites de seguridad sin justificación
- No usar nombres de columnas que no hayas validado
- No ejecutar operaciones de lote en transacciones largas sin chunking
- No asumir que todas las bases de datos soportan todas las operaciones

---

## 🏆 Conclusión

Las Operaciones de Lote de VersaORM te proporcionan el poder de manejar grandes volúmenes de datos con:
- **Rendimiento excepcional** (hasta 20x más rápido que operaciones individuales)
- **Seguridad incorporada** con validación automática
- **Flexibilidad total** para diferentes casos de uso
- **Control granular** sobre el procesamiento

¡Experimenta con estas poderosas herramientas y lleva el rendimiento de tus aplicaciones al siguiente nivel!
