# ⚠️ Nota Modo PHP / PDO
Esta guía funciona íntegramente en modo PHP. Cuando el núcleo nativo vuelva, los mismos métodos aprovecharán optimizaciones internas automáticamente.

# 🔄 Operaciones UPSERT y REPLACE INTO - Guía Completa

¡Descubre las poderosas operaciones de inserción/actualización inteligente de VersaORM! Estas funcionalidades te permiten manejar datos de manera eficiente cuando no sabes si un registro existe o no.

## 🎯 ¿Qué son las Operaciones UPSERT y REPLACE?

Las operaciones **UPSERT** y **REPLACE INTO** resuelven el problema común de "insertar si no existe, actualizar si existe" de manera atómica y eficiente, sin necesidad de consultas separadas de verificación.

### 🔄 UPSERT vs REPLACE INTO

| Característica | UPSERT | REPLACE INTO |
|---------------|--------|--------------|
| **Comportamiento** | Actualiza solo las columnas especificadas | Reemplaza COMPLETAMENTE el registro |
| **Compatibilidad** | Todas las BD (con fallback) | Solo MySQL |
| **Preserva datos** | ✅ Sí (columnas no especificadas) | ❌ No (puede perder datos) |
| **Flexibilidad** | ✅ Control granular de columnas | ❌ Todo o nada |
| **Uso recomendado** | La mayoría de casos | Casos específicos de reemplazo total |

---

## 🎯 Operación UPSERT (Individual)

### ¿Qué es UPSERT?

**UPSERT** combina INSERT y UPDATE en una operación atómica. Si el registro no existe (basado en claves únicas), lo inserta. Si existe, actualiza solo las columnas especificadas.

### Ejemplo SQL vs VersaORM

```sql
-- SQL Tradicional (requiere múltiples consultas)
-- 1. Verificar si existe
SELECT COUNT(*) FROM products WHERE sku = 'PROD001';

-- 2a. Si no existe, insertar
INSERT INTO products (sku, name, price, stock)
VALUES ('PROD001', 'Laptop Pro', 1500.00, 10);

-- 2b. Si existe, actualizar
UPDATE products
SET name = 'Laptop Pro', price = 1500.00, stock = 10, updated_at = NOW()
WHERE sku = 'PROD001';
```

```php
// VersaORM - Una sola operación atómica
$result = $orm->table('products')->upsert(
    [
        'sku' => 'PROD001',
        'name' => 'Laptop Pro',
        'price' => 1500.00,
        'stock' => 10
    ],
    ['sku'], // Claves únicas para detectar duplicados
    ['name', 'price', 'stock'] // Columnas a actualizar si existe (opcional)
);
```

### Sintaxis Básica

```php
$result = $orm->table('table_name')->upsert(
    $data,              // Datos del registro
    $uniqueKeys,        // Claves únicas para detectar duplicados
    $updateColumns      // Columnas a actualizar si existe (opcional)
);
```

### Ejemplos Prácticos

#### 1. UPSERT Básico - Producto en Inventario

```php
// Actualizar inventario - insertar si es nuevo, actualizar stock si existe
$productData = [
    'sku' => 'LAPTOP-001',
    'name' => 'MacBook Pro 16"',
    'price' => 2499.99,
    'stock' => 25,
    'category' => 'Electronics',
    'description' => 'Potente laptop para profesionales'
];

$result = $orm->table('products')->upsert(
    $productData,
    ['sku'], // El SKU es único
    ['name', 'price', 'stock'] // Solo actualizar estos campos si ya existe
);

// Resultado:
// Si es nuevo: ['status' => 'success', 'operation' => 'inserted', 'rows_affected' => 1]
// Si existe: ['status' => 'success', 'operation' => 'updated', 'rows_affected' => 1, 'update_columns' => ['name', 'price', 'stock']]
```

#### 2. UPSERT con Múltiples Claves Únicas

```php
// Usuario con email y username únicos
$userData = [
    'username' => 'john_doe',
    'email' => 'john@example.com',
    'full_name' => 'John Doe',
    'department' => 'Engineering',
    'salary' => 75000
];

$result = $orm->table('employees')->upsert(
    $userData,
    ['username', 'email'], // Ambos deben ser únicos
    ['full_name', 'department', 'salary'] // Actualizar solo estos campos
);
```

#### 3. UPSERT Completo (Sin Restricciones de Columnas)

```php
// Actualizar todo el perfil de usuario
$userProfile = [
    'user_id' => 123,
    'bio' => 'Desarrollador Full Stack con 5 años de experiencia',
    'website' => 'https://johndoe.dev',
    'location' => 'Madrid, España',
    'linkedin' => 'https://linkedin.com/in/johndoe',
    'updated_at' => date('Y-m-d H:i:s')
];

// Si no especificas updateColumns, actualiza todos los campos
$result = $orm->table('user_profiles')->upsert(
    $userProfile,
    ['user_id']
    // Sin updateColumns = actualiza todos los campos si existe
);
```

#### 4. UPSERT con Campos Calculados

```php
// Estadísticas de usuario con contadores
$stats = [
    'user_id' => 456,
    'total_posts' => 42,
    'total_comments' => 128,
    'reputation_score' => 1250,
    'last_activity' => date('Y-m-d H:i:s')
];

$result = $orm->table('user_stats')->upsert(
    $stats,
    ['user_id'],
    ['total_posts', 'total_comments', 'reputation_score', 'last_activity']
);
```

### Casos de Uso Comunes para UPSERT

#### 1. Sincronización con APIs Externas

```php
// Sincronizar datos de productos desde API de proveedor
function syncProductFromAPI($orm, $apiProduct) {
    $productData = [
        'sku' => $apiProduct['code'],
        'name' => $apiProduct['name'],
        'price' => $apiProduct['price'],
        'stock' => $apiProduct['available_qty'],
        'supplier_id' => $apiProduct['supplier'],
        'last_sync' => date('Y-m-d H:i:s')
    ];

    return $orm->table('products')->upsert(
        $productData,
        ['sku'],
        ['name', 'price', 'stock', 'last_sync'] // Preservar supplier_id original
    );
}
```

#### 2. Contadores de Actividad

```php
// Actualizar estadísticas de página
function updatePageStats($orm, $pageId, $views = 1) {
    $statsData = [
        'page_id' => $pageId,
        'view_count' => $views,
        'last_viewed' => date('Y-m-d H:i:s'),
        'updated_at' => date('Y-m-d H:i:s')
    ];

    return $orm->table('page_statistics')->upsert(
        $statsData,
        ['page_id'],
        ['view_count', 'last_viewed', 'updated_at']
    );
}
```

#### 3. Configuraciones de Usuario

```php
// Guardar preferencias de usuario
function saveUserPreference($orm, $userId, $key, $value) {
    $preferenceData = [
        'user_id' => $userId,
        'preference_key' => $key,
        'preference_value' => $value,
        'updated_at' => date('Y-m-d H:i:s')
    ];

    return $orm->table('user_preferences')->upsert(
        $preferenceData,
        ['user_id', 'preference_key'],
        ['preference_value', 'updated_at']
    );
}
```

---

## 🔄 Operación REPLACE INTO (Solo MySQL)

### ¿Qué es REPLACE INTO?

**REPLACE INTO** es una operación específica de MySQL que elimina completamente el registro existente (si existe) e inserta uno nuevo. ⚠️ **ADVERTENCIA**: Puede causar pérdida de datos en columnas no especificadas.

### Cuándo Usar REPLACE INTO

✅ **Usar cuando**:
- Necesitas reemplazo COMPLETO del registro
- Trabajas exclusivamente con MySQL
- Quieres comportamiento de "todo o nada"
- Los datos nuevos contienen TODOS los campos necesarios

❌ **NO usar cuando**:
- Quieres preservar algunos campos existentes
- Trabajas con múltiples tipos de base de datos
- Los datos pueden estar incompletos

### Ejemplo SQL vs VersaORM

```sql
-- SQL (MySQL)
REPLACE INTO products (sku, name, price, description)
VALUES ('PROD001', 'Laptop Pro Updated', 1600.00, 'Nueva descripción completa');
```

```php
// VersaORM
$result = $orm->table('products')->replaceInto([
    'sku' => 'PROD001',
    'name' => 'Laptop Pro Updated',
    'price' => 1600.00,
    'description' => 'Nueva descripción completa'
]);
```

### Sintaxis Básica

```php
$result = $orm->table('table_name')->replaceInto($data);
```

### Ejemplos Prácticos

#### 1. Reemplazo Completo de Configuración

```php
// Reemplazar configuración completa del sistema
$systemConfig = [
    'config_key' => 'email_settings',
    'smtp_host' => 'new-smtp.example.com',
    'smtp_port' => 587,
    'smtp_username' => 'noreply@newdomain.com',
    'smtp_password' => 'new_secure_password',
    'encryption' => 'tls',
    'updated_at' => date('Y-m-d H:i:s')
];

$result = $orm->table('system_config')->replaceInto($systemConfig);
// Si existe config_key, reemplaza TODOS los campos
// Si no existe, inserta como nuevo registro
```

#### 2. Reemplazo de Cache Completo

```php
// Actualizar cache de usuario completo
$cacheData = [
    'user_id' => 123,
    'cache_key' => 'user_profile',
    'cache_data' => json_encode($fullUserProfile),
    'expiry_time' => date('Y-m-d H:i:s', strtotime('+1 hour')),
    'created_at' => date('Y-m-d H:i:s')
];

$result = $orm->table('user_cache')->replaceInto($cacheData);
```

#### 3. Logs de Sesión Únicos

```php
// Reemplazar información de sesión activa
$sessionData = [
    'session_id' => $sessionId,
    'user_id' => $userId,
    'ip_address' => $_SERVER['REMOTE_ADDR'],
    'user_agent' => $_SERVER['HTTP_USER_AGENT'],
    'last_activity' => date('Y-m-d H:i:s'),
    'data' => serialize($sessionContent)
];

$result = $orm->table('active_sessions')->replaceInto($sessionData);
```

### ⚠️ Diferencias Importantes: UPSERT vs REPLACE INTO

#### Ejemplo Comparativo

Supongamos que tienes este registro existente:
```php
// Registro existente en la tabla 'products'
[
    'sku' => 'PROD001',
    'name' => 'Laptop Original',
    'price' => 1200.00,
    'description' => 'Descripción original',
    'category' => 'Electronics',
    'stock' => 15,
    'created_at' => '2024-01-01 10:00:00'
]
```

#### Con UPSERT:
```php
$newData = [
    'sku' => 'PROD001',
    'name' => 'Laptop Actualizado',
    'price' => 1300.00
];

$result = $orm->table('products')->upsert(
    $newData,
    ['sku'],
    ['name', 'price']
);

// Resultado final:
[
    'sku' => 'PROD001',
    'name' => 'Laptop Actualizado',      // ✅ Actualizado
    'price' => 1300.00,                  // ✅ Actualizado
    'description' => 'Descripción original', // ✅ Preservado
    'category' => 'Electronics',         // ✅ Preservado
    'stock' => 15,                       // ✅ Preservado
    'created_at' => '2024-01-01 10:00:00' // ✅ Preservado
]
```

#### Con REPLACE INTO:
```php
$newData = [
    'sku' => 'PROD001',
    'name' => 'Laptop Actualizado',
    'price' => 1300.00
];

$result = $orm->table('products')->replaceInto($newData);

// Resultado final:
[
    'sku' => 'PROD001',
    'name' => 'Laptop Actualizado',      // ✅ Actualizado
    'price' => 1300.00,                  // ✅ Actualizado
    'description' => NULL,               // ❌ PERDIDO
    'category' => NULL,                  // ❌ PERDIDO
    'stock' => NULL,                     // ❌ PERDIDO
    'created_at' => NULL                 // ❌ PERDIDO
]
```

---

## 🛡️ Características de Seguridad

### Validación de Claves Únicas

```php
// ❌ Error: Clave única faltante en los datos
$result = $orm->table('products')->upsert(
    ['name' => 'Producto sin SKU', 'price' => 100],
    ['sku'] // sku no está en los datos
);
// VersaORMException: Record is missing unique key: sku

// ✅ Correcto: Todos los campos únicos presentes
$result = $orm->table('products')->upsert(
    ['sku' => 'PROD001', 'name' => 'Producto Válido', 'price' => 100],
    ['sku']
);
```

### Protección contra Inyección SQL

```php
// ❌ Error: Nombre de columna malicioso
$result = $orm->table('products')->upsert(
    ['sku; DROP TABLE products; --' => 'malicious'],
    ['sku']
);
// VersaORMException: Invalid or malicious column name detected

// ✅ Seguro: Nombres de columnas válidos
$result = $orm->table('products')->upsert(
    ['product_sku' => 'PROD001', 'product_name' => 'Safe Product'],
    ['product_sku']
);
```

### Validación de Identificadores

```php
// ❌ Error: Nombre de clave única inválido
$result = $orm->table('users')->upsert(
    ['username' => 'john', 'email' => 'john@example.com'],
    ['user; DROP TABLE users; --'] // Clave única maliciosa
);
// VersaORMException: Invalid unique key name detected

// ✅ Correcto: Nombres válidos
$result = $orm->table('users')->upsert(
    ['username' => 'john', 'email' => 'john@example.com'],
    ['username', 'email']
);
```

---

## ⚡ Optimización y Rendimiento

### Mejores Prácticas

#### 1. Uso Eficiente de Claves Únicas

```php
// ✅ Buena práctica: Usar índices únicos existentes
$result = $orm->table('products')->upsert(
    $productData,
    ['sku'], // SKU ya tiene índice único
    ['name', 'price']
);

// ❌ Evitar: Usar columnas sin índices únicos
$result = $orm->table('products')->upsert(
    $productData,
    ['description'], // description no tiene índice único - será lento
    ['name', 'price']
);
```

#### 2. Minimizar Columnas de Actualización

```php
// ✅ Eficiente: Solo actualizar campos necesarios
$result = $orm->table('products')->upsert(
    $productData,
    ['sku'],
    ['price', 'stock'] // Solo campos que realmente cambian
);

// ❌ Ineficiente: Actualizar todos los campos
$result = $orm->table('products')->upsert(
    $productData,
    ['sku']
    // Sin updateColumns = actualiza TODOS los campos
);
```

#### 3. Batch vs Individual

```php
// Para múltiples registros, usa las operaciones batch
if (count($products) > 10) {
    // ✅ Más eficiente para múltiples registros
    $result = $orm->table('products')->upsertMany(
        $products,
        ['sku'],
        ['name', 'price', 'stock']
    );
} else {
    // ✅ Más eficiente para registros individuales
    foreach ($products as $product) {
        $result = $orm->table('products')->upsert(
            $product,
            ['sku'],
            ['name', 'price', 'stock']
        );
    }
}
```

---

## 🚨 Manejo de Errores

### Errores Comunes y Soluciones

#### 1. Claves Únicas Faltantes

```php
try {
    $result = $orm->table('users')->upsert(
        ['email' => 'john@example.com', 'name' => 'John'],
        ['user_id'] // user_id no está en los datos
    );
} catch (VersaORMException $e) {
    if (strpos($e->getMessage(), 'missing unique key') !== false) {
        echo "Error: Debes incluir todos los campos de claves únicas\n";
        echo "Solución: Agregar 'user_id' a los datos o usar diferente clave única\n";
    }
}
```

#### 2. Driver No Compatible (REPLACE INTO)

```php
try {
    // En PostgreSQL o SQLite
    $result = $orm->table('products')->replaceInto($data);
} catch (VersaORMException $e) {
    if (strpos($e->getMessage(), 'only supported for MySQL') !== false) {
        echo "Error: REPLACE INTO solo funciona en MySQL\n";
        echo "Solución: Usar upsert() en su lugar\n";

        // Alternativa segura
        $result = $orm->table('products')->upsert($data, ['sku']);
    }
}
```

#### 3. Validación de Estructura

```php
try {
    $result = $orm->table('products')->upsert(
        ['sku' => 'PROD001', 'invalid-column-name!' => 'value'],
        ['sku']
    );
} catch (VersaORMException $e) {
    if (strpos($e->getMessage(), 'Invalid or malicious column') !== false) {
        echo "Error: Nombre de columna no válido\n";
        echo "Solución: Usar solo nombres alfanuméricos y guiones bajos\n";
    }
}
```

### Función de Manejo Robusto

```php
function safeUpsert($orm, $table, $data, $uniqueKeys, $updateColumns = []) {
    try {
        // Validar que todos los campos únicos están presentes
        foreach ($uniqueKeys as $key) {
            if (!array_key_exists($key, $data)) {
                throw new InvalidArgumentException("Missing required unique key: {$key}");
            }
        }

        // Ejecutar upsert
        $result = $orm->table($table)->upsert($data, $uniqueKeys, $updateColumns);

        // Log exitoso
        error_log("UPSERT successful for {$table}: " . json_encode($result));

        return $result;

    } catch (VersaORMException $e) {
        // Log error específico de VersaORM
        error_log("VersaORM UPSERT error in {$table}: " . $e->getMessage());
        return ['status' => 'error', 'message' => 'Database operation failed', 'details' => $e->getMessage()];

    } catch (Exception $e) {
        // Log error general
        error_log("General UPSERT error in {$table}: " . $e->getMessage());
        return ['status' => 'error', 'message' => 'Operation failed', 'details' => $e->getMessage()];
    }
}

// Uso
$result = safeUpsert($orm, 'products', $productData, ['sku'], ['name', 'price']);
if ($result['status'] === 'error') {
    echo "Error en la operación: " . $result['message'] . "\n";
}
```

---

## 📊 Casos de Uso Avanzados

### 1. Sistema de Cache Inteligente

```php
class SmartCache {
    private $orm;

    public function __construct($orm) {
        $this->orm = $orm;
    }

    public function set($key, $value, $ttl = 3600) {
        $cacheData = [
            'cache_key' => $key,
            'cache_value' => serialize($value),
            'expires_at' => date('Y-m-d H:i:s', time() + $ttl),
            'created_at' => date('Y-m-d H:i:s'),
            'hit_count' => 1
        ];

        return $this->orm->table('cache')->upsert(
            $cacheData,
            ['cache_key'],
            ['cache_value', 'expires_at', 'created_at'] // Preservar hit_count en updates
        );
    }

    public function incrementHits($key) {
        // Usar SQL raw para incremento atómico
        return $this->orm->table('cache')
            ->where('cache_key', '=', $key)
            ->update(['hit_count' => 'hit_count + 1']);
    }
}
```

### 2. Sistema de Puntuación de Usuario

```php
function updateUserScore($orm, $userId, $points, $reason) {
    // Actualizar puntuación total
    $scoreData = [
        'user_id' => $userId,
        'total_points' => $points,
        'last_updated' => date('Y-m-d H:i:s'),
        'update_reason' => $reason
    ];

    $scoreResult = $orm->table('user_scores')->upsert(
        $scoreData,
        ['user_id'],
        ['total_points', 'last_updated', 'update_reason']
    );

    // Registrar el cambio en el historial
    $historyData = [
        'user_id' => $userId,
        'points_change' => $points,
        'reason' => $reason,
        'timestamp' => date('Y-m-d H:i:s'),
        'previous_total' => 0 // Se calculará después
    ];

    $orm->table('score_history')->insert($historyData);

    return $scoreResult;
}
```

### 3. Sistema de Configuración Jerárquica

```php
class HierarchicalConfig {
    private $orm;

    public function set($category, $key, $value, $scope = 'global') {
        $configData = [
            'config_category' => $category,
            'config_key' => $key,
            'config_value' => json_encode($value),
            'config_scope' => $scope,
            'updated_at' => date('Y-m-d H:i:s'),
            'is_active' => true
        ];

        return $this->orm->table('app_config')->upsert(
            $configData,
            ['config_category', 'config_key', 'config_scope'],
            ['config_value', 'updated_at']
        );
    }

    public function get($category, $key, $scope = 'global') {
        $config = $this->orm->table('app_config')
            ->where('config_category', '=', $category)
            ->where('config_key', '=', $key)
            ->where('config_scope', '=', $scope)
            ->where('is_active', '=', true)
            ->firstArray();

        return $config ? json_decode($config['config_value'], true) : null;
    }
}
```

---

## 🎓 Resumen de Mejores Prácticas

### ✅ Para UPSERT:

1. **Usa índices únicos existentes** como claves de detección
2. **Especifica updateColumns** para control preciso
3. **Valida datos antes** de la operación
4. **Maneja errores** apropiadamente
5. **Prefiere upsert sobre replaceInto** para compatibilidad

### ✅ Para REPLACE INTO:

1. **Solo en MySQL** y cuando necesites reemplazo total
2. **Incluye TODOS los campos** necesarios en los datos
3. **Úsalo para configuraciones** que deben ser completas
4. **Evítalo para datos parciales** o incrementales

### ❌ Qué evitar:

- No usar claves únicas sin índices (rendimiento)
- No ignorar manejo de errores
- No usar REPLACE INTO con datos incompletos
- No asumir compatibilidad entre bases de datos
- No usar operaciones individuales para grandes volúmenes

---

## 🏆 Conclusión

Las operaciones **UPSERT** y **REPLACE INTO** de VersaORM te proporcionan:

- ✨ **Simplicidad**: Una operación en lugar de múltiples consultas
- ⚡ **Rendimiento**: Operaciones atómicas optimizadas
- 🛡️ **Seguridad**: Validación automática y protección contra inyección
- 🔧 **Flexibilidad**: Control granular sobre qué actualizar
- 🎯 **Precisión**: Comportamiento predecible y consistente

¡Domina estas herramientas y simplifica tu lógica de persistencia de datos!
