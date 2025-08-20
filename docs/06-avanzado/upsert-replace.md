# UPSERT y REPLACE

Las operaciones UPSERT (UPDATE + INSERT) y REPLACE te permiten manejar inserciones condicionales y actualizaciones inteligentes, evitando errores de duplicadossimplificando la lógica de tu aplicación.

## Conceptos Clave

- **UPSERT**: Actualiza si existe, inserta si no existe
- **REPLACE**: Elimina y reinserta el registro completo
- **ON DUPLICATE KEY**: Manejo automático de claves duplicadas
- **Idempotencia**: Operaciones que pueden ejecutarse múltiples veces con el mismo resultado

## upsert() - Insertar o Actualizar

### Ejemplo Básico

```php
<?php
require_once 'bootstrap.php';

try {
    // Datos del usuario que puede existir o no
    $userData = [
        'email' => 'juan@example.com',
        'name' => 'Juan Pérez Actualizado',
        'active' => true,
        'last_login' => date('Y-m-d H:i:s')
    ];

    // UPSERT: actualiza si existe el email, inserta si no existe
    $result = $orm->table('users')->upsert($userData, ['email']);

    if ($result['action'] === 'inserted') {
        echo "Usuario insertado con ID: " . $result['id'] . "\n";
    } else {
        echo "Usuario actualizado con ID: " . $result['id'] . "\n";
    }

} catch (VersaORMException $e) {
    echo "Error en UPSERT: " . $e->getMessage() . "\n";
}
```

**SQL Equivalente (MySQL):**
```sql
INSERT INTO users (email, name, active, last_login)
VALUES ('juan@example.com', 'Juan Pérez Actualizado', 1, '2024-01-15 10:30:00')
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    active = VALUES(active),
    last_login = VALUES(last_login);
```

**Devuelve:** Array con 'action' ('inserted' o 'updated') e 'id' del registro

### UPSERT con Múltiples Claves Únicas

```php
<?php
try {
    // Configuración de usuario con múltiples identificadores únicos
    $userConfig = [
        'email' => 'admin@example.com',
        'username' => 'admin_user',
        'name' => 'Administrador',
        'role' => 'admin',
        'settings' => json_encode(['theme' => 'dark', 'notifications' => true])
    ];

    // UPSERT basado en email O username
    $result = $orm->table('users')->upsert($userConfig, ['email', 'username']);

    echo "Operación: " . $result['action'] . "\n";
    echo "ID del usuario: " . $result['id'] . "\n";

    // Verificar el resultado
    $user = $orm->table('users')->find($result['id']);
    echo "Usuario final: " . $user['name'] . " (" . $user['email'] . ")\n";

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

**SQL Equivalente:**
```sql
-- MySQL
INSERT INTO users (email, username, name, role, settings)
VALUES ('admin@example.com','admin_user','Administrador','admin','{"theme":"dark","notifications":true}')
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    role = VALUES(role),
    settings = VALUES(settings);

-- PostgreSQL
INSERT INTO users (email, username, name, role, settings)
VALUES ('admin@example.com','admin_user','Administrador','admin','{"theme":"dark","notifications":true}')
ON CONFLICT (email, username) DO UPDATE SET
    name = EXCLUDED.name,
    role = EXCLUDED.role,
    settings = EXCLUDED.settings;

-- SQLite
INSERT INTO users (email, username, name, role, settings)
VALUES ('admin@example.com','admin_user','Administrador','admin','{"theme":"dark","notifications":true}')
ON CONFLICT(email, username) DO UPDATE SET
    name = excluded.name,
    role = excluded.role,
    settings = excluded.settings;
```

### UPSERT Masivo

```php
<?php
try {
    // Datos de múltiples usuarios para UPSERT
    $usersData = [
        ['email' => 'user1@example.com', 'name' => 'Usuario 1', 'active' => true],
        ['email' => 'user2@example.com', 'name' => 'Usuario 2', 'active' => false],
        ['email' => 'user3@example.com', 'name' => 'Usuario 3', 'active' => true]
    ];

    // Mejor opción: usar upsertMany para lotes grandes
    $result = $orm->table('users')->upsertMany($usersData, ['email']);
    // $result = ['affected' => int] - Número total de filas afectadas (insertadas + actualizadas)
    echo "Usuarios insertados/actualizados: " . $result['affected'] . "\n";

} catch (VersaORMException $e) {
    echo "Error en UPSERT masivo: " . $e->getMessage() . "\n";
}
```

**SQL Equivalente (patrón repetido por cada elemento):**
**Tip para principiantes:** Para lotes grandes, usa upsertMany en vez de bucles individuales para mejor rendimiento y menor riesgo de errores.
```sql
-- Ejemplo para user1@example.com (los demás igual cambiando valores)
-- MySQL
INSERT INTO users (email, name, active)
VALUES ('user1@example.com','Usuario 1',1)
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    active = VALUES(active);

-- PostgreSQL
INSERT INTO users (email, name, active)
VALUES ('user1@example.com','Usuario 1', TRUE)
ON CONFLICT (email) DO UPDATE SET
    name = EXCLUDED.name,
    active = EXCLUDED.active;

-- SQLite
INSERT INTO users (email, name, active)
VALUES ('user1@example.com','Usuario 1',1)
ON CONFLICT(email) DO UPDATE SET
    name = excluded.name,
    active = excluded.active;
```

## replace() - Reemplazar Registro Completo

### Ejemplo Básico

```php
<?php
try {
    // Datos completos del registro a reemplazar
    $postData = [
        'id' => 5, // ID del post a reemplazar
        'title' => 'Título Completamente Nuevo',
        'content' => 'Contenido completamente reescrito',
        'user_id' => 2,
        'published' => true,
        'created_at' => date('Y-m-d H:i:s')
    ];

    // REPLACE: elimina el registro existente y crea uno nuevo
    $result = $orm->table('posts')->replaceInto($postData);
    // $result = ['status'=>'success', 'id'=>int|string|null]
    echo "Post reemplazado con ID: " . $result['id'] . "\n";
    // Verificar el reemplazo
    $post = $orm->table('posts')->find($result['id']);
    echo "Nuevo título: " . $post['title'] . "\n";

} catch (VersaORMException $e) {
    echo "Error en REPLACE: " . $e->getMessage() . "\n";
}
```

**SQL Equivalente:**
```sql
REPLACE INTO posts (id, title, content, user_id, published, created_at)
VALUES (5, 'Título Completamente Nuevo', 'Contenido completamente reescrito', 2, 1, '2024-01-15 10:30:00');
```

**Devuelve:** ID del registro reemplazado
**Tip para principiantes:** REPLACE elimina el registro anterior y crea uno nuevo. Asegúrate de incluir todos los campos requeridos para evitar errores de NOT NULL.

### REPLACE sin ID (Basado en Claves Únicas)

```php
<?php
try {
    // Configuración de aplicación (clave única: 'key')
    $configData = [
        'key' => 'app_theme',
        'value' => 'dark_mode',
        'description' => 'Tema de la aplicación',
        'updated_at' => date('Y-m-d H:i:s')
    ];

    // REPLACE basado en la clave única 'key'
    $id = $orm->table('app_config')->replace($configData);

    echo "Configuración reemplazada con ID: $id\n";

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

**SQL Equivalente:**
```sql
-- MySQL (REPLACE elimina y reinserta)
REPLACE INTO app_config (`key`, `value`, description, updated_at)
VALUES ('app_theme','dark_mode','Tema de la aplicación','2024-01-15 10:30:00');

-- PostgreSQL (simular REPLACE con UPSERT completo)
INSERT INTO app_config ("key", "value", description, updated_at)
VALUES ('app_theme','dark_mode','Tema de la aplicación','2024-01-15 10:30:00')
ON CONFLICT ("key") DO UPDATE SET
    value = EXCLUDED.value,
    description = EXCLUDED.description,
    updated_at = EXCLUDED.updated_at;

-- SQLite (INSERT OR REPLACE borra fila y crea nueva conservando rowid si coincide PK)
INSERT OR REPLACE INTO app_config (key, value, description, updated_at)
VALUES ('app_theme','dark_mode','Tema de la aplicación','2024-01-15 10:30:00');
```

## Comparación: UPSERT vs REPLACE

### Diferencias Clave

```php
<?php
// Datos originales en la base de datos
// users: id=1, name='Juan', email='juan@example.com', active=true, created_at='2024-01-01'

// UPSERT - Actualiza solo campos especificados
$upsertData = [
    'email' => 'juan@example.com',
    'name' => 'Juan Actualizado'
    // 'active' y 'created_at' se mantienen sin cambios
];

$result1 = $orm->table('users')->upsert($upsertData, ['email']);
// Resultado: id=1, name='Juan Actualizado', email='juan@example.com', active=true, created_at='2024-01-01'

// REPLACE - Reemplaza el registro completo
$replaceData = [
    'id' => 1,
    'email' => 'juan@example.com',
    'name' => 'Juan Reemplazado'
    // 'active' será NULL o valor por defecto, 'created_at' será la fecha actual
];

$result2 = $orm->table('users')->replace($replaceData);
// Resultado: id=1, name='Juan Reemplazado', email='juan@example.com', active=NULL, created_at='2024-01-15'
```

**SQL Equivalente:**
```sql
-- UPSERT (preserva columnas no incluidas)
-- MySQL
INSERT INTO users (email, name)
VALUES ('juan@example.com','Juan Actualizado')
ON DUPLICATE KEY UPDATE
    name = VALUES(name);

-- PostgreSQL
INSERT INTO users (email, name)
VALUES ('juan@example.com','Juan Actualizado')
ON CONFLICT (email) DO UPDATE SET
    name = EXCLUDED.name;

-- SQLite
INSERT INTO users (email, name)
VALUES ('juan@example.com','Juan Actualizado')
ON CONFLICT(email) DO UPDATE SET
    name = excluded.name;

-- REPLACE (no preserva lo omitido)
-- MySQL
REPLACE INTO users (id, email, name)
VALUES (1,'juan@example.com','Juan Reemplazado');

-- PostgreSQL (simulación usando UPSERT con todos los campos que quieras forzar)
INSERT INTO users (id, email, name)
VALUES (1,'juan@example.com','Juan Reemplazado')
ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    name = EXCLUDED.name;

-- SQLite (INSERT OR REPLACE)
INSERT OR REPLACE INTO users (id, email, name)
VALUES (1,'juan@example.com','Juan Reemplazado');
```

### Cuándo Usar Cada Uno

```php
<?php
// ✅ Usar UPSERT cuando:
// - Quieres preservar campos no especificados
// - Actualizas parcialmente registros existentes
// - Manejas datos de formularios o APIs

$profileUpdate = [
    'user_id' => 123,
    'bio' => 'Nueva biografía del usuario',
    'website' => 'https://nuevositio.com'
    // Otros campos del perfil se mantienen
];
$orm->table('user_profiles')->upsert($profileUpdate, ['user_id']);

// ✅ Usar REPLACE cuando:
// - Quieres reemplazar completamente el registro
// - Tienes todos los datos necesarios
// - Implementas cache o configuraciones

$cacheEntry = [
    'cache_key' => 'user_permissions_123',
    'data' => json_encode($permissions),
    'expires_at' => date('Y-m-d H:i:s', strtotime('+1 hour'))
];
$orm->table('cache')->replace($cacheEntry);
```

**SQL Equivalente:**
```sql
-- UPSERT perfil
INSERT INTO user_profiles (user_id, bio, website)
VALUES (123,'Nueva biografía del usuario','https://nuevositio.com')
ON CONFLICT (user_id) DO UPDATE SET
    bio = EXCLUDED.bio,
    website = EXCLUDED.website;

-- REPLACE cache (MySQL)
REPLACE INTO cache (cache_key, data, expires_at)
VALUES ('user_permissions_123','{"read":true,"write":true}','2024-01-15 11:30:00');

-- Cache UPSERT estilo PostgreSQL
INSERT INTO cache (cache_key, data, expires_at)
VALUES ('user_permissions_123','{"read":true,"write":true}','2024-01-15 11:30:00')
ON CONFLICT (cache_key) DO UPDATE SET
    data = EXCLUDED.data,
    expires_at = EXCLUDED.expires_at;
```

## Casos de Uso Avanzados

### Sistema de Configuración

```php
<?php
class ConfigManager {
    private $orm;

    public function __construct($orm) {
        $this->orm = $orm;
    }

    public function setSetting($key, $value, $description = null) {
        $data = [
            'key' => $key,
            'value' => is_array($value) ? json_encode($value) : $value,
            'updated_at' => date('Y-m-d H:i:s')
        ];

        if ($description !== null) {
            $data['description'] = $description;
        }

        return $this->orm->table('settings')->upsert($data, ['key']);
    }

    public function getSetting($key, $default = null) {
        $setting = $this->orm->table('settings')
            ->where('key', '=', $key)
            ->first();

        if (!$setting) {
            return $default;
        }

        $value = $setting['value'];

        // Intentar decodificar JSON
        $decoded = json_decode($value, true);
        return $decoded !== null ? $decoded : $value;
    }
}

// Uso del sistema de configuración
$config = new ConfigManager($orm);

// Establecer configuraciones (UPSERT automático)
$config->setSetting('app_name', 'Mi Aplicación');
$config->setSetting('features', ['dark_mode' => true, 'notifications' => false]);
$config->setSetting('max_users', 1000);

// Obtener configuraciones
echo "Nombre de la app: " . $config->getSetting('app_name') . "\n";
$features = $config->getSetting('features', []);
echo "Modo oscuro: " . ($features['dark_mode'] ? 'Sí' : 'No') . "\n";
```

**SQL Equivalente:**
```sql
-- UPSERT de configuración (clave única key)
INSERT INTO settings (key, value, updated_at, description)
VALUES ('features','{"dark_mode":true,"notifications":false}','2024-01-15 10:30:00',NULL)
ON CONFLICT (key) DO UPDATE SET
    value = EXCLUDED.value,
    updated_at = EXCLUDED.updated_at,
    description = COALESCE(EXCLUDED.description, settings.description);

-- SELECT para lectura
SELECT key, value, updated_at, description FROM settings WHERE key = 'features' LIMIT 1;
```

### Cache con Expiración

```php
<?php
class CacheManager {
    private $orm;

    public function __construct($orm) {
        $this->orm = $orm;
    }

    public function set($key, $data, $ttl = 3600) {
        $cacheData = [
            'cache_key' => $key,
            'data' => json_encode($data),
            'expires_at' => date('Y-m-d H:i:s', time() + $ttl),
            'created_at' => date('Y-m-d H:i:s')
        ];

        // REPLACE para sobrescribir completamente la entrada de cache
        return $this->orm->table('cache')->replace($cacheData);
    }

    public function get($key) {
        $cache = $this->orm->table('cache')
            ->where('cache_key', '=', $key)
            ->where('expires_at', '>', date('Y-m-d H:i:s'))
            ->first();

        return $cache ? json_decode($cache['data'], true) : null;
    }

    public function cleanup() {
        // Limpiar entradas expiradas
        return $this->orm->table('cache')
            ->where('expires_at', '<=', date('Y-m-d H:i:s'))
            ->deleteMany();
    }
}

// Uso del cache
$cache = new CacheManager($orm);

// Guardar en cache (REPLACE automático)
$userData = ['id' => 123, 'name' => 'Juan', 'permissions' => ['read', 'write']];
$cache->set('user_123', $userData, 1800); // 30 minutos

// Recuperar del cache
$cachedUser = $cache->get('user_123');
if ($cachedUser) {
    echo "Usuario desde cache: " . $cachedUser['name'] . "\n";
} else {
    echo "Cache expirado o no encontrado\n";
}

// Limpiar cache expirado
$cleaned = $cache->cleanup();
echo "Entradas de cache limpiadas: $cleaned\n";
```

**SQL Equivalente:**
```sql
-- Guardar (REPLACE / UPSERT según motor)
REPLACE INTO cache (cache_key, data, expires_at, created_at)
VALUES ('user_123','{"id":123,"name":"Juan","permissions":["read","write"]}','2024-01-15 11:00:00','2024-01-15 10:30:00');

-- SELECT vigente
SELECT cache_key, data, expires_at FROM cache
WHERE cache_key = 'user_123'
    AND expires_at > '2024-01-15 10:30:00'
LIMIT 1;

-- Delete expirados
DELETE FROM cache WHERE expires_at <= '2024-01-15 10:30:00';
```

### Sincronización de Datos Externos

```php
<?php
function syncExternalUsers($externalUsers) {
    $orm = VersaORM::getInstance();
    $synced = ['inserted' => 0, 'updated' => 0, 'errors' => []];

    foreach ($externalUsers as $externalUser) {
        try {
            $userData = [
                'external_id' => $externalUser['id'],
                'name' => $externalUser['full_name'],
                'email' => $externalUser['email_address'],
                'active' => $externalUser['is_active'],
                'last_sync' => date('Y-m-d H:i:s')
            ];

            // UPSERT basado en external_id
            $result = $orm->table('users')->upsert($userData, ['external_id']);

            if ($result['action'] === 'inserted') {
                $synced['inserted']++;
            } else {
                $synced['updated']++;
            }

        } catch (VersaORMException $e) {
            $synced['errors'][] = [
                'external_id' => $externalUser['id'],
                'error' => $e->getMessage()
            ];
        }
    }

    return $synced;
}

// Simular datos externos
$externalData = [
    ['id' => 'ext_001', 'full_name' => 'Usuario Externo 1', 'email_address' => 'ext1@example.com', 'is_active' => true],
    ['id' => 'ext_002', 'full_name' => 'Usuario Externo 2', 'email_address' => 'ext2@example.com', 'is_active' => false]
];

$result = syncExternalUsers($externalData);
echo "Sincronización completada:\n";
echo "- Insertados: " . $result['inserted'] . "\n";
echo "- Actualizados: " . $result['updated'] . "\n";
echo "- Errores: " . count($result['errors']) . "\n";
```

**SQL Equivalente (patrón por usuario externo):**
```sql
-- Para id ext_001
INSERT INTO users (external_id, name, email, active, last_sync)
VALUES ('ext_001','Usuario Externo 1','ext1@example.com', TRUE, '2024-01-15 10:30:00')
ON CONFLICT (external_id) DO UPDATE SET
    name = EXCLUDED.name,
    email = EXCLUDED.email,
    active = EXCLUDED.active,
    last_sync = EXCLUDED.last_sync;
```

## Consideraciones de Performance

### Benchmarking UPSERT vs INSERT/UPDATE Manual

```php
<?php
function benchmarkUpsertVsManual($testData) {
    $orm = VersaORM::getInstance();

    // Método manual (lento)
    $start = microtime(true);
    foreach ($testData as $data) {
        $existing = $orm->table('users')->where('email', '=', $data['email'])->first();
        if ($existing) {
            $orm->table('users')->where('id', '=', $existing['id'])->update($data);
        } else {
            $orm->table('users')->insert($data);
        }
    }
    $manualTime = microtime(true) - $start;

    // Limpiar datos de prueba
    $orm->table('users')->where('email', 'LIKE', '%test%')->deleteMany();

    // Método UPSERT (rápido)
    $start = microtime(true);
    foreach ($testData as $data) {
        $orm->table('users')->upsert($data, ['email']);
    }
    $upsertTime = microtime(true) - $start;

    echo "Tiempo método manual: " . number_format($manualTime, 4) . "s\n";
    echo "Tiempo UPSERT: " . number_format($upsertTime, 4) . "s\n";
    echo "Mejora de performance: " . number_format($manualTime / $upsertTime, 2) . "x más rápido\n";
}
```

**SQL Equivalente (patrones):**
```sql
-- Método manual (pseudo secuencia por registro)
SELECT id, email FROM users WHERE email = :email LIMIT 1; -- si existe
UPDATE users SET name = :name, active = :active WHERE id = :id; -- cuando existe
INSERT INTO users (email, name, active) VALUES (:email, :name, :active); -- cuando NO existe

-- UPSERT (una sola sentencia por registro)
INSERT INTO users (email, name, active)
VALUES (:email, :name, :active)
ON CONFLICT (email) DO UPDATE SET
    name = EXCLUDED.name,
    active = EXCLUDED.active;
```

## Errores Comunes y Soluciones

### Error: Claves Únicas Faltantes

```php
<?php
// ❌ Incorrecto: No especificar claves únicas para UPSERT
try {
    $data = ['name' => 'Juan', 'email' => 'juan@example.com'];
    $orm->table('users')->upsert($data); // Error: falta especificar claves únicas
} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}

// ✅ Correcto: Especificar claves únicas
$data = ['name' => 'Juan', 'email' => 'juan@example.com'];
$result = $orm->table('users')->upsert($data, ['email']);
```

**SQL Equivalente:**
```sql
-- Sin especificar clave única (conceptual) el ORM no puede construir ON CONFLICT/ON DUPLICATE KEY.
-- Con clave única:
INSERT INTO users (name, email)
VALUES ('Juan','juan@example.com')
ON CONFLICT (email) DO UPDATE SET
    name = EXCLUDED.name;
```

### Error: REPLACE con Datos Incompletos

```php
<?php
// ❌ Incorrecto: REPLACE sin todos los campos requeridos
try {
    $data = ['id' => 1, 'name' => 'Juan']; // Falta 'email' que es NOT NULL
    $orm->table('users')->replace($data);
} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}

// ✅ Correcto: Incluir todos los campos requeridos
$data = [
    'id' => 1,
    'name' => 'Juan',
    'email' => 'juan@example.com',
    'active' => true
];
$orm->table('users')->replace($data);
```

**SQL Equivalente:**
```sql
-- Fallará (NOT NULL email)
REPLACE INTO users (id, name) VALUES (1,'Juan');
-- Correcto incluyendo campos NOT NULL
REPLACE INTO users (id, name, email, active)
VALUES (1,'Juan','juan@example.com',1);
```

## Siguiente Paso

Ahora que dominas UPSERT y REPLACE, continúa con [Transacciones](transacciones.md) para aprender a manejar operaciones complejas con integridad de datos.
