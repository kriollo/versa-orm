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

## findInBatches() - Lectura en Lotes (Procesamiento Secuencial)

Permite procesar grandes cantidades de registros sin cargarlos todos en memoria. Recupera lotes (paginados con `LIMIT/OFFSET`) y ejecuta un callback por cada lote.

### Firma

```php
VersaModel::findInBatches(
    string $table,
    callable $callback,
    int $batchSize = 1000,
    ?string $conditions = null,
    array $bindings = [],
    string $orderBy = 'id'
): void;
```

### Parámetros

- table: Nombre de la tabla a consultar.
- callback: Función que recibe un array de modelos (`VersaModel[]`) correspondientes al lote actual.
- batchSize: Cantidad máxima de registros por lote (por defecto 1000).
- conditions / bindings: Condición SQL raw opcional + valores asociados (igual semántica que en `findAll`).
- orderBy: Columna usada para paginar determinísticamente (debe ser estable y preferentemente indexada).

### Ejemplo Básico

```php
use VersaORM\VersaModel;

VersaModel::findInBatches('users', function(array $users) {
    foreach ($users as $u) {
        echo "Procesando usuario #{$u->id}: {$u->name}\n";
    }
}, 500); // lotes de 500
```

### Ejemplo con Condición y Bindings

```php
// Procesar solo usuarios activos en lotes de 100
VersaModel::findInBatches('users', function(array $lote) {
    foreach ($lote as $u) {
        indexarUsuario($u);
    }
}, 100, 'status = ?', ['active']);
```

### Ejemplo con Manejo de Errores por Lote

```php
VersaModel::findInBatches('users', function(array $lote) use ($logger) {
    foreach ($lote as $user) {
        try {
            procesar($user);
        } catch (Throwable $e) {
            $logger->error('Fallo procesando usuario', [
                'id' => $user->id,
                'error' => $e->getMessage(),
            ]);
        }
    }
}, 1000);
```

### Comportamiento y Garantías

1. Se detiene cuando un lote devuelve menos registros que `batchSize`.
2. No invoca el callback si no hay resultados (condición vacía).
3. Usa paginación por desplazamiento (`OFFSET`), adecuada para datasets medianos; para millones de filas con escrituras concurrentes considerar en el futuro keyset pagination.
4. El orden debe ser estable para evitar duplicados u omisiones (por defecto `id`).

### Casos de Uso

- Exportaciones (CSV/JSON) masivas.
- ETL / migraciones incrementales.
- Reindexación de buscadores.
- Cálculo de métricas batch.

### Buenas Prácticas

- Ajustar `batchSize` según peso de fila (500–5000 suele equilibrar I/O y memoria).
- Asegurar índice sobre la columna de `orderBy`.
- Evitar mutar/borrar filas ya procesadas dentro del mismo recorrido (si es inevitable, usar estrategia por rangos de ID).
- Manejar excepciones dentro del callback para no abortar el flujo completo.

### Edge Cases

| Escenario | Resultado |
|-----------|-----------|
| Tabla vacía / condición sin coincidencias | No se llama al callback |
| batchSize > total | Una única invocación con todos los registros |
| conditions con un solo placeholder simple | ORM puede optimizar internamente usando where() en lugar de whereRaw |

---

> Nota: Próximas versiones podrían incluir variantes basadas en cursores para mejorar rendimiento en tablas con alta tasa de escrituras concurrentes.

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

## Casos de Uso Reales (Patrones Prácticos)

Esta sección conecta cada operación batch con situaciones habituales en productos reales. Incluye patrones, elección de método y fragmentos que puedes adaptar.

### Resumen Rápido de Escenarios

| Escenario | Métodos Clave | Objetivo | Nota de Performance |
|-----------|---------------|----------|---------------------|
| Exportación masiva a CSV | findInBatches | Stream sin agotar memoria | Ajusta batchSize según ancho de fila |
| Reindexación motor búsqueda | findInBatches + callback | Re-construir índice externo | Añade sleep opcional para no saturar API |
| Campaña de emails segmentada | findInBatches | Envío por lotes + throttling | Registra offset o última ID procesada |
| Backfill de columna derivada | findInBatches + updateMany | Completar datos calculados | Usa commit por lote si la lógica es compleja |
| Archivado + purga histórica | findInBatches + insertMany + deleteMany | Mover datos fríos | Ejecuta dentro de ventana de baja carga |
| Migración multi-tenant | insertMany (chunk) | Copiar datos aislados | Valida FK y desactiva triggers si procede |
| Limpieza/normalización | updateMany | Unificar formatos | Divide reglas en pasos idempotentes |
| Anonimización GDPR | findInBatches + updateMany | Enmascarar PII | Mantén log de hash reversible si está permitido |
| Agregaciones precomputadas | findInBatches + tabla summary | Reducir costo de consultas analíticas | Recalcula incrementalmente |
| Streaming a API externa | findInBatches | Sincronizar a sistema remoto | Implementa reintentos exponenciales |

---

### 1. Exportación Masiva a CSV (Streaming)

```php
$fh = fopen('export_users.csv', 'w');
fputcsv($fh, ['id','name','email','active']);

VersaModel::findInBatches('users', function(array $lote) use ($fh) {
    foreach ($lote as $u) {
        fputcsv($fh, [$u->id, $u->name, $u->email, (int)$u->active]);
    }
}, 1000, 'active = ?', [true]);

fclose($fh);
```

Clave: No cargas todos los usuarios en memoria; cada lote se vuelca inmediatamente.

### 2. Reindexación en Motor de Búsqueda (Elasticsearch / Meilisearch)

```php
VersaModel::findInBatches('products', function(array $products) use ($searchClient) {
    $payload = [];
    foreach ($products as $p) {
        $payload[] = [
            'id' => $p->id,
            'title' => $p->title,
            'price' => $p->price,
            'tags' => explode(',', (string)$p->tags)
        ];
    }
    $searchClient->bulkIndex($payload); // API externa
    // Opcional: usleep(50000); // ritmo
}, 500, 'status = ?', ['published']);
```

### 3. Campaña de Emails Segmentada con Throttling

```php
$envios = 0;
VersaModel::findInBatches('users', function(array $users) use (&$envios, $mailer) {
    foreach ($users as $u) {
        $mailer->sendTemplate('promo_q3', $u->email, ['name' => $u->name]);
        $envios++;
        if ($envios % 100 == 0) {
            // Pausa breve para no golpear el provider
            usleep(200000); // 200ms
        }
    }
}, 200, 'opt_in = ?', [true]);
```

### 4. Backfill de Columna Derivada (Ej: hash_email)

```php
VersaModel::findInBatches('users', function(array $lote) use ($orm) {
    $updates = [];
    foreach ($lote as $u) {
        if (!$u->hash_email) {
            $updates[] = [ 'id' => $u->id, 'hash_email' => hash('sha256', strtolower($u->email)) ];
        }
    }
    if ($updates) {
        // Actualizaciones individuales agregadas; si existe un updateManyByIds puedes adaptarlo
        foreach ($updates as $row) {
            $orm->table('users')->where('id','=', $row['id'])->updateMany(['hash_email' => $row['hash_email']]);
        }
    }
}, 300, 'hash_email IS NULL');
```

### 5. Archivado y Purga

```php
$cutoff = date('Y-m-d', strtotime('-18 months'));
VersaModel::findInBatches('audit_logs', function(array $logs) use ($orm) {
    if (!$logs) return;
    $bulk = [];
    $ids = [];
    foreach ($logs as $log) {
        $bulk[] = $log->toArray(); // Mismo esquema en tabla archive_audit_logs
        $ids[] = $log->id;
    }
    $orm->table('archive_audit_logs')->insertMany($bulk);
    $orm->table('audit_logs')->whereIn('id', $ids)->deleteMany();
}, 1000, 'created_at < ?', [$cutoff]);
```

### 6. Migración Multi-Tenant (Copiar Datos de un Cliente)

```php
function migrarTenant(int $tenantId, int $nuevoTenantId, VersaORM $orm) {
    VersaModel::findInBatches('orders', function(array $orders) use ($orm, $nuevoTenantId) {
        $chunk = [];
        foreach ($orders as $o) {
            $data = $o->toArray();
            $data['tenant_id'] = $nuevoTenantId;
            unset($data['id']); // Autoincrement
            $chunk[] = $data;
        }
        if ($chunk) {
            $orm->table('orders')->insertMany($chunk);
        }
    }, 500, 'tenant_id = ?', [$tenantId]);
}
```

### 7. Normalización / Limpieza Masiva

```php
// Normalizar emails a minúsculas en lotes
VersaModel::findInBatches('users', function(array $users) use ($orm) {
    foreach ($users as $u) {
        $lower = strtolower($u->email);
        if ($u->email !== $lower) {
            $orm->table('users')->where('id','=', $u->id)->updateMany(['email' => $lower]);
        }
    }
}, 400);
```

### 8. Anonimización (GDPR / Derecho al Olvido)

```php
VersaModel::findInBatches('users', function(array $users) use ($orm) {
    foreach ($users as $u) {
        if ($u->deleted_at && !$u->anonymized_at) {
            $orm->table('users')
                ->where('id','=', $u->id)
                ->updateMany([
                    'name' => 'anon-'.$u->id,
                    'email' => null,
                    'hash_email' => null,
                    'anonymized_at' => date('Y-m-d H:i:s')
                ]);
        }
    }
}, 300, 'deleted_at IS NOT NULL AND anonymized_at IS NULL');
```

### 9. Agregaciones Precomputadas (Tabla Summary)

```php
// Recalcular totales de ventas por usuario
$acumulados = [];
VersaModel::findInBatches('orders', function(array $orders) use (&$acumulados) {
    foreach ($orders as $o) {
        $acumulados[$o->user_id] = ($acumulados[$o->user_id] ?? 0) + (float)$o->total;
    }
}, 1000, 'created_at >= ?', [date('Y-m-01')]);

// Persistir resumen
foreach ($acumulados as $userId => $monto) {
    $orm->table('sales_summary')
        ->where('user_id','=', $userId)
        ->updateMany(['monthly_amount' => $monto]);
}
```

### 10. Streaming a API Externa con Reintentos y Registro

```php
VersaModel::findInBatches('invoices', function(array $invoices) use ($apiClient, $logger) {
    foreach ($invoices as $inv) {
        $payload = $inv->toArray();
        $intentos = 0;
        while ($intentos < 3) {
            try {
                $apiClient->sendInvoice($payload);
                break; // Éxito
            } catch (Throwable $e) {
                $intentos++;
                if ($intentos >= 3) {
                    $logger->error('Fallo enviando invoice', ['id' => $inv->id, 'error' => $e->getMessage()]);
                } else {
                    usleep(100000 * $intentos); // backoff exponencial simple
                }
            }
        }
    }
}, 200, 'status = ?', ['pending_sync']);
```

### Patrón: Rango por ID vs OFFSET

Para tablas enormes (decenas de millones) `OFFSET` degrada. Alternativa: paginar por rango usando la columna incremental (ej. `id`).

```php
$lastId = 0;
while (true) {
    $lote = $orm->table('events')
        ->where('id', '>', $lastId)
        ->orderBy('id', 'ASC')
        ->limit(1000)
        ->get();
    if (!$lote) break;
    foreach ($lote as $row) {
        procesar($row);
        $lastId = max($lastId, $row['id']);
    }
}
```

Comparar: `findInBatches` usa `OFFSET`; este patrón evita el costo acumulado y evita saltos si se borran filas.

### Checklist de Decisión Rápida

- ¿Solo lectura secuencial? -> `findInBatches`.
- ¿Inserción de dataset externo? -> `insertMany` (chunk si > 10k filas).
- ¿Actualización masiva homogénea? -> `updateMany`.
- ¿Purgar / limpiar / archivar? -> `findInBatches` + `insertMany` (archivos) + `deleteMany`.
- ¿Optimización heavy y tabla gigante? -> Rango por ID (o futura keyset) + lotes más pequeños (200-500).

### Consideraciones de Observabilidad

Registra métricas básicas por lote: tamaño, duración, errores. Ejemplo rápido:

```php
$metrics = ['lotes' => 0, 'procesados' => 0];
$t0 = microtime(true);
VersaModel::findInBatches('users', function(array $lote) use (&$metrics) {
    $metrics['lotes']++;
    $metrics['procesados'] += count($lote);
}, 1000);
$elapsed = microtime(true) - $t0;
echo "Lotes: {$metrics['lotes']} | Registros: {$metrics['procesados']} | seg: ".number_format($elapsed,2)." | r/s: ".number_format($metrics['procesados']/$elapsed,0)."\n";
```

---

Con estos patrones tienes una guía práctica para aplicar operaciones batch de forma segura, eficiente y mantenible en sistemas productivos.


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
