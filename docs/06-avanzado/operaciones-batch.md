# Operaciones Batch

Las operaciones batch te permiten procesar grandes volúmenes de datos de manera eficiente, reduciendo significativamente el número de consultas a la base de datos.

## Conceptos Clave

- **Batch Operations**: Operaciones que procesan múltiples registros en una sola consulta
- **Performance**: Mejora dramática del rendimiento al reducir round-trips a la base de datos
- **Transacciones**: Las operaciones batch se ejecutan dentro de transacciones automáticas

## insertMany() - Inserción Masiva

### Ejemplo Básico

```php
<?php
require_once 'bootstrap.php';

try {
    // Preparar datos para inserción masiva
    $users = [
        ['name' => 'Juan Pérez', 'email' => 'juan@example.com', 'active' => true],
        ['name' => 'María García', 'email' => 'maria@example.com', 'active' => true],
        ['name' => 'Carlos López', 'email' => 'carlos@example.com', 'active' => false],
        ['name' => 'Ana Martín', 'email' => 'ana@example.com', 'active' => true]
    ];

    // Inserción masiva
    $insertedIds = $orm->table('users')->insertMany($users);

    echo "Usuarios insertados: " . count($insertedIds) . "\n";
    echo "IDs generados: " . implode(', ', $insertedIds) . "\n";

} catch (VersaORMException $e) {
    echo "Error en inserción masiva: " . $e->getMessage() . "\n";
}
```

**SQL Equivalente:**
```sql
INSERT INTO users (name, email, active) VALUES
('Juan Pérez', 'juan@example.com', 1),
('María García', 'maria@example.com', 1),
('Carlos López', 'carlos@example.com', 0),
('Ana Martín', 'ana@example.com', 1);
```

**Devuelve:** Array de IDs de los registros insertados

### Ejemplo con Validación

```php
<?php
try {
    $posts = [
        ['title' => 'Primer Post', 'content' => 'Contenido del primer post', 'user_id' => 1],
        ['title' => 'Segundo Post', 'content' => 'Contenido del segundo post', 'user_id' => 2],
        ['title' => 'Tercer Post', 'content' => 'Contenido del tercer post', 'user_id' => 1]
    ];

    // Validar que todos los user_id existen antes de insertar
    $userIds = array_unique(array_column($posts, 'user_id'));
    $existingUsers = $orm->table('users')
        ->whereIn('id', $userIds)
        ->pluck('id');

    if (count($existingUsers) !== count($userIds)) {
        throw new Exception('Algunos usuarios no existen');
    }

    $insertedIds = $orm->table('posts')->insertMany($posts);
    echo "Posts insertados: " . count($insertedIds) . "\n";

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

## updateMany() - Actualización Masiva

### Actualización con Condiciones

```php
<?php
try {
    // Actualizar múltiples registros con la misma condición
    $affectedRows = $orm->table('users')
        ->where('active', '=', false)
        ->updateMany(['active' => true, 'updated_at' => date('Y-m-d H:i:s')]);

    echo "Usuarios activados: $affectedRows\n";

} catch (VersaORMException $e) {
    echo "Error en actualización masiva: " . $e->getMessage() . "\n";
}
```

**SQL Equivalente:**
```sql
UPDATE users
SET active = 1, updated_at = '2024-01-15 10:30:00'
WHERE active = 0;
```

**Devuelve:** Número de filas afectadas (integer)

### Actualización por IDs Específicos

```php
<?php
try {
    // Actualizar usuarios específicos
    $userIds = [1, 3, 5, 7];
    $updates = ['last_login' => date('Y-m-d H:i:s')];

    $affectedRows = $orm->table('users')
        ->whereIn('id', $userIds)
        ->updateMany($updates);

    echo "Usuarios actualizados: $affectedRows\n";

    // Verificar la actualización
    $updatedUsers = $orm->table('users')
        ->whereIn('id', $userIds)
        ->select(['id', 'name', 'last_login'])
        ->getAll();

    foreach ($updatedUsers as $user) {
        echo "Usuario {$user['name']}: {$user['last_login']}\n";
    }

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```
**SQL Equivalente:**
```sql
UPDATE users SET last_login = '2025-08-18 10:12:00' WHERE id IN (1,3,5,7);
```

## deleteMany() - Eliminación Masiva

### Eliminación con Condiciones

```php
<?php
try {
    // Eliminar posts antiguos (más de 1 año)
    $oneYearAgo = date('Y-m-d', strtotime('-1 year'));

    $deletedRows = $orm->table('posts')
        ->where('created_at', '<', $oneYearAgo)
        ->where('published', '=', false)
        ->deleteMany();

    echo "Posts eliminados: $deletedRows\n";

} catch (VersaORMException $e) {
    echo "Error en eliminación masiva: " . $e->getMessage() . "\n";
}
```

**SQL Equivalente:**
```sql
DELETE FROM posts
WHERE created_at < '2023-01-15'
AND published = 0;
```

**Devuelve:** Número de filas eliminadas (integer)

### Eliminación por IDs con Verificación

```php
<?php
try {
    // IDs de posts a eliminar
    $postIds = [10, 15, 20, 25];

    // Verificar que los posts existen y pertenecen al usuario actual
    $userId = 1; // ID del usuario actual
    $validPosts = $orm->table('posts')
        ->whereIn('id', $postIds)
        ->where('user_id', '=', $userId)
        ->pluck('id');

    if (empty($validPosts)) {
        echo "No se encontraron posts válidos para eliminar\n";
        return;
    }

    $deletedRows = $orm->table('posts')
        ->whereIn('id', $validPosts)
        ->deleteMany();

    echo "Posts eliminados: $deletedRows\n";
    echo "IDs eliminados: " . implode(', ', $validPosts) . "\n";

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```
**SQL Equivalente (tras verificación de ownership):**
```sql
DELETE FROM posts WHERE id IN (10,15,20,25);
```

## Operaciones Batch con Transacciones

### Ejemplo Completo con Manejo de Errores

```php
<?php
try {
    // Iniciar transacción para operaciones batch
    $orm->beginTransaction();

    // 1. Insertar nuevos usuarios
    $newUsers = [
        ['name' => 'Usuario Batch 1', 'email' => 'batch1@example.com'],
        ['name' => 'Usuario Batch 2', 'email' => 'batch2@example.com']
    ];
    $userIds = $orm->table('users')->insertMany($newUsers);
    echo "Usuarios insertados: " . count($userIds) . "\n";

    // 2. Crear posts para estos usuarios
    $newPosts = [];
    foreach ($userIds as $userId) {
        $newPosts[] = [
            'title' => "Post del usuario $userId",
            'content' => "Contenido generado automáticamente",
            'user_id' => $userId,
            'published' => true
        ];
    }
    $postIds = $orm->table('posts')->insertMany($newPosts);
    echo "Posts insertados: " . count($postIds) . "\n";

    // 3. Actualizar estadísticas de usuarios
    $orm->table('users')
        ->whereIn('id', $userIds)
        ->updateMany(['post_count' => 1]);

    // Confirmar transacción
    $orm->commit();
    echo "Operación batch completada exitosamente\n";

} catch (Exception $e) {
    // Revertir en caso de error
    $orm->rollback();
    echo "Error en operación batch: " . $e->getMessage() . "\n";
    echo "Transacción revertida\n";
}
```
**SQL Equivalente aproximado dentro de la transacción:**
```sql
-- BEGIN
INSERT INTO users (name,email) VALUES ('Usuario Batch 1','batch1@example.com'),('Usuario Batch 2','batch2@example.com');
INSERT INTO posts (title,content,user_id,published) VALUES ('Post del usuario 101','Contenido generado automáticamente',101,1), ('Post del usuario 102','Contenido generado automáticamente',102,1);
UPDATE users SET post_count = 1 WHERE id IN (101,102);
-- COMMIT (o ROLLBACK si hay excepción)
```

## Optimización y Mejores Prácticas

### Tamaño de Lote Óptimo

```php
<?php
function processBatchData($data, $batchSize = 1000) {
    $orm = VersaORM::getInstance();
    $batches = array_chunk($data, $batchSize);
    $totalInserted = 0;

    foreach ($batches as $batch) {
        try {
            $ids = $orm->table('large_table')->insertMany($batch);
            $totalInserted += count($ids);
            echo "Lote procesado: " . count($ids) . " registros\n";

        } catch (VersaORMException $e) {
            echo "Error en lote: " . $e->getMessage() . "\n";
            // Continuar con el siguiente lote o detener según la lógica de negocio
        }
    }

    return $totalInserted;
}

// Procesar 10,000 registros en lotes de 500
$largeDataset = generateLargeDataset(10000);
$inserted = processBatchData($largeDataset, 500);
echo "Total insertado: $inserted registros\n";
```

### Monitoreo de Performance

```php
<?php
function benchmarkBatchOperation() {
    $orm = VersaORM::getInstance();

    // Preparar datos de prueba
    $testData = [];
    for ($i = 0; $i < 5000; $i++) {
        $testData[] = [
            'name' => "Usuario Test $i",
            'email' => "test$i@example.com",
            'active' => ($i % 2 === 0)
        ];
    }

    // Benchmark inserción individual vs batch
    $start = microtime(true);

    // Método tradicional (lento)
    /*
    foreach ($testData as $user) {
        $orm->table('users')->insert($user);
    }
    */

    // Método batch (rápido)
    $ids = $orm->table('users')->insertMany($testData);

    $end = microtime(true);
    $duration = $end - $start;

    echo "Tiempo de ejecución: " . number_format($duration, 4) . " segundos\n";
    echo "Registros procesados: " . count($ids) . "\n";
    echo "Registros por segundo: " . number_format(count($ids) / $duration, 2) . "\n";
}
```

## Errores Comunes y Soluciones

### Error: Datos Inconsistentes

```php
<?php
// ❌ Incorrecto: Arrays con diferentes claves
$badData = [
    ['name' => 'Juan', 'email' => 'juan@example.com'],
    ['name' => 'María', 'email' => 'maria@example.com', 'active' => true], // Clave extra
    ['nombre' => 'Carlos', 'email' => 'carlos@example.com'] // Clave diferente
];

// ✅ Correcto: Estructura consistente
$goodData = [
    ['name' => 'Juan', 'email' => 'juan@example.com', 'active' => true],
    ['name' => 'María', 'email' => 'maria@example.com', 'active' => true],
    ['name' => 'Carlos', 'email' => 'carlos@example.com', 'active' => false]
];
```

### Error: Violación de Restricciones

```php
<?php
try {
    $users = [
        ['name' => 'Usuario 1', 'email' => 'duplicado@example.com'],
        ['name' => 'Usuario 2', 'email' => 'duplicado@example.com'] // Email duplicado
    ];

    $orm->table('users')->insertMany($users);

} catch (VersaORMException $e) {
    if (strpos($e->getMessage(), 'Duplicate entry') !== false) {
        echo "Error: Email duplicado detectado\n";
        // Manejar duplicados individualmente o filtrar datos
    }
}
```

## Siguiente Paso

Ahora que dominas las operaciones batch, continúa con [UPSERT y REPLACE](upsert-replace.md) para aprender sobre operaciones de inserción condicional.
