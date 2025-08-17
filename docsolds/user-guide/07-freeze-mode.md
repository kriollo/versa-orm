# Modo Freeze - Protección de Esquema

## Introducción

El **Modo Freeze** es una característica de seguridad avanzada de VersaORM-PHP que permite proteger el esquema de la base de datos contra modificaciones accidentales o no autorizadas. Cuando está activo, el modo freeze bloquea todas las operaciones DDL (Data Definition Language) que puedan alterar la estructura de la base de datos.

## ¿Qué es el Modo Freeze?

El modo freeze actúa como un "mecanismo de protección" que:

- **Previene alteraciones de esquema** durante la ejecución de la aplicación
- **Bloquea operaciones DDL** como CREATE, ALTER, DROP, TRUNCATE
- **Protege contra modificaciones accidentales** del esquema en producción
- **Registra intentos de violación** para auditoría de seguridad
- **Permite control granular** por modelo específico o global
- **🆕 Habilita creación automática de campos** (estilo RedBeanPHP) cuando está desactivado

## Creación Automática de Campos (Modo Fluid)

Cuando el **modo freeze está DESACTIVADO**, VersaORM adopta un comportamiento similar a **RedBeanPHP**:

### Características del Modo Fluid

- **Creación automática de columnas**: Si asignas un valor a una propiedad que no existe en la tabla, VersaORM creará automáticamente la columna
- **Detección automática de tipos**: Infiere el tipo de columna SQL basado en el valor PHP asignado
- **Desarrollo ágil**: Permite prototipar rápidamente sin definir esquemas previamente

### Ejemplo de Creación Automática

```php
use VersaORM\VersaORM;
use VersaORM\VersaModel;

$orm = new VersaORM($config);
VersaModel::setORM($orm);

// Asegurar que freeze está desactivado
$orm->freeze(false);

class User extends VersaModel {
    protected string $table = 'users';
    protected array $fillable = ['*']; // Permitir todos los campos
}

// Crear un usuario con campos que NO existen en la tabla
$user = new User('users', $orm);
$user->name = "Juan Pérez";              // VARCHAR(255)
$user->email = "juan@example.com";       // VARCHAR(255)
$user->age = 30;                         // INT
$user->salary = 50000.50;                // DECIMAL(10,2)
$user->is_active = true;                 // BOOLEAN
$user->metadata = ['role' => 'admin'];   // JSON

// Al guardar, VersaORM creará automáticamente todas las columnas faltantes
$user->store(); // ✅ Crea: email, age, salary, is_active, metadata

// Las siguientes operaciones funcionarán sin problemas
$users = User::findAll('users');
echo $users[0]->email; // "juan@example.com"
```

### Mapeo Automático de Tipos

VersaORM detecta automáticamente los tipos SQL basándose en los valores PHP:

| Tipo PHP | Tipo SQL | Ejemplo |
|----------|----------|---------|
| `string` (≤255 chars) | `VARCHAR(255)` | `"Texto corto"` |
| `string` (≤65535 chars) | `TEXT` | `"Texto largo..."` |
| `string` (>65535 chars) | `LONGTEXT` | `"Texto muy largo..."` |
| `int` | `INT` | `42` |
| `float` | `DECIMAL(10,2)` | `3.14159` |
| `bool` | `BOOLEAN` | `true` / `false` |
| `array` / `object` | `JSON` | `['key' => 'value']` |
| `null` | `VARCHAR(255)` | `null` (tipo por defecto) |

### Seguridad y Control

```php
// ✅ Modo desarrollo - Creación automática habilitada
$orm->freeze(false);
$user->new_field = "Se creará automáticamente";
$user->store(); // Crea la columna 'new_field'

// 🔒 Modo producción - Creación automática bloqueada
$orm->freeze(true);
$user->another_field = "No se creará";
$user->store(); // ❌ Lanza excepción
```

## Tipos de Freeze

### 1. Freeze Global

Bloquea **todas** las operaciones DDL en toda la aplicación:

```php
use VersaORM\VersaORM;

$orm = new VersaORM($config);

// Activar freeze global
$orm->freeze(true);

// Verificar estado
if ($orm->isFrozen()) {
    echo "Modo freeze global está activo";
}

// Desactivar freeze global
$orm->freeze(false);
```

### 2. Freeze por Modelo

Bloquea operaciones DDL solo para modelos específicos:

```php
use VersaORM\VersaModel;

// Freeze por modelo específico
$orm->freezeModel(User::class, true);

// Verificar si un modelo está congelado
if ($orm->isModelFrozen(User::class)) {
    echo "El modelo User está congelado";
}

// Liberar un modelo específico
$orm->freezeModel(User::class, false);
```

### 3. Freeze desde Modelos

Los modelos también pueden gestionar su propio estado freeze:

```php
use VersaORM\VersaModel;

class User extends VersaModel
{
    protected string $table = 'users';
}

// Configurar ORM globalmente
VersaModel::setORM($orm);

// Congelar este modelo
User::freeze(true);

// Verificar estado
if (User::isFrozen()) {
    echo "El modelo User está congelado";
}

// Liberar
User::freeze(false);
```

## Operaciones Bloqueadas

### Operaciones DDL Típicas

Cuando el freeze está activo, las siguientes operaciones son bloqueadas:

- `CREATE TABLE` / `createTable`
- `DROP TABLE` / `dropTable`
- `ALTER TABLE` / `alterTable`
- `TRUNCATE TABLE` / `truncateTable`
- `ADD COLUMN` / `addColumn`
- `DROP COLUMN` / `dropColumn`
- `MODIFY COLUMN` / `modifyColumn`
- `RENAME COLUMN` / `renameColumn`
- `CREATE INDEX` / `createIndex`
- `DROP INDEX` / `dropIndex`
- `ADD FOREIGN KEY` / `addForeignKey`
- `DROP FOREIGN KEY` / `dropForeignKey`
- `RENAME TABLE` / `renameTable`

### Consultas SQL Raw

El sistema también detecta y bloquea consultas SQL raw que contengan operaciones DDL:

```php
// Estas consultas serán bloqueadas en modo freeze
$orm->exec("CREATE TABLE users (id INT PRIMARY KEY)");
$orm->exec("ALTER TABLE users ADD COLUMN email VARCHAR(255)");
$orm->exec("DROP TABLE old_table");
```

## Casos de Uso

### 1. Protección en Producción

```php
// En el entorno de producción
if (app()->environment('production')) {
    $orm->freeze(true);
    echo "Modo freeze activado para producción";
}
```

### 2. Desarrollo Controlado

```php
// Durante desarrollo, proteger ciertas tablas críticas
$orm->freezeModel(ConfigTable::class, true);
$orm->freezeModel(UserPermissions::class, true);

// Permitir modificaciones en tablas de desarrollo
$orm->freezeModel(TestTable::class, false);
```

### 3. Auditoría y Compliance

```php
// Activar freeze antes de operaciones críticas
$orm->freeze(true);

try {
    // Ejecutar operaciones de negocio
    performCriticalBusinessOperation();
} finally {
    // Desactivar freeze después de las operaciones
    $orm->freeze(false);
}
```

## Manejo de Excepciones

### Violaciones de Freeze

Cuando se intenta ejecutar una operación DDL en modo freeze, se lanza una `VersaORMException`:

```php
try {
    $orm->freeze(true);
    $orm->exec("CREATE TABLE test (id INT)");
} catch (VersaORMException $e) {
    if ($e->getCode() === 'FREEZE_VIOLATION') {
        echo "Operación bloqueada por modo freeze: " . $e->getMessage();
        echo "Detalles: " . json_encode($e->getContext());
    }
}
```

### Información Detallada de Errores

En modo debug, las excepciones incluyen información detallada:

```php
// Activar debug para obtener más información
$config['debug'] = true;
$orm = new VersaORM($config);
$orm->freeze(true);

try {
    $orm->exec("DROP TABLE users");
} catch (VersaORMException $e) {
    echo $e->getMessage();
    // Output: "Operation 'DROP' blocked by global freeze mode.
    //          DDL operations are not allowed when freeze mode is active.
    //          To allow this operation:
    //          - Disable global freeze: $orm->freeze(false)"
}
```

## Logging y Auditoría

### Registro de Activaciones

El sistema registra automáticamente las activaciones/desactivaciones de freeze:

```php
$orm->freeze(true);  // Se registra como "FREEZE_MODE_ACTIVATED"
$orm->freeze(false); // Se registra como "FREEZE_MODE_DEACTIVATED"

$orm->freezeModel(User::class, true);  // Se registra como "MODEL_FROZEN"
$orm->freezeModel(User::class, false); // Se registra como "MODEL_UNFROZEN"
```

### Registro de Violaciones

Los intentos de violación se registran para auditoría:

```php
// Este intento será registrado como "FREEZE_VIOLATION_ATTEMPT"
try {
    $orm->freeze(true);
    $orm->exec("CREATE TABLE test (id INT)");
} catch (VersaORMException $e) {
    // El intento queda registrado en los logs de seguridad
}
```

### Ubicación de Logs

Los logs se guardan en:
- `logs/YYYY-MM-DD.log` - Logs generales
- `logs/security-YYYY-MM-DD.log` - Logs de seguridad específicos

## Mejores Prácticas

### 1. Usar en Producción

```php
// Configuración recomendada para producción
class ProductionConfig
{
    public static function setupFreeze(VersaORM $orm): void
    {
        // Activar freeze global en producción
        $orm->freeze(true);

        // Registrar el cambio
        error_log("PRODUCTION: Freeze mode activated");
    }
}
```

### 2. Freeze Temporal

```php
// Para operaciones que requieren protección temporal
function criticalOperation(VersaORM $orm): void
{
    $wasFreezed = $orm->isFrozen();

    try {
        $orm->freeze(true);
        // Realizar operaciones críticas aquí
        performBusinessLogic();
    } finally {
        // Restaurar estado original
        $orm->freeze($wasFreezed);
    }
}
```

### 3. Configuración por Entorno

```php
// config/database.php
return [
    'production' => [
        'driver' => 'mysql',
        'host' => env('DB_HOST'),
        // ... otras configuraciones ...
        'freeze_on_boot' => true, // Activar freeze al inicializar
    ],
    'development' => [
        'driver' => 'mysql',
        'host' => 'localhost',
        // ... otras configuraciones ...
        'freeze_on_boot' => false, // Permitir modificaciones en desarrollo
    ],
];
```

### 4. Testing con Freeze

```php
// En tests, verificar que el freeze funciona correctamente
class FreezeTest extends TestCase
{
    public function testFreezeBlocksDDL(): void
    {
        $orm = new VersaORM($this->config);
        $orm->freeze(true);

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('blocked by global freeze mode');

        $orm->exec("CREATE TABLE test (id INT)");
    }

    public function testFreezeAllowsDML(): void
    {
        $orm = new VersaORM($this->config);
        $orm->freeze(true);

        // Las operaciones DML deben seguir funcionando
        $result = $orm->table('users')->where('id', '=', 1)->get();
        $this->assertIsArray($result);
    }
}
```

## Limitaciones

### 1. Solo Operaciones DDL

El freeze **NO** bloquea operaciones DML (Data Manipulation Language):
- `SELECT`, `INSERT`, `UPDATE`, `DELETE` siguen funcionando normalmente
- Solo se bloquean operaciones que modifican la estructura del esquema

### 2. Detección de SQL Raw

La detección en consultas SQL raw se basa en patrones de texto:
- Puede no detectar consultas DDL muy complejas o ofuscadas
- Se recomienda usar métodos del ORM cuando sea posible

### 3. Alcance por Sesión

El estado freeze es por instancia de `VersaORM`:
- No persiste entre diferentes ejecuciones de la aplicación
- Debe ser configurado en cada inicialización

## Integración con el Núcleo Rust

El modo freeze está implementado tanto en PHP como en el núcleo Rust:

### Lado PHP
- Gestiona el estado freeze (`$isFrozen`, `$frozenModels`)
- Envía el estado al núcleo Rust en cada operación
- Maneja logging y excepciones de alto nivel

### Lado Rust
- Valida operaciones DDL antes de ejecutarlas
- Bloquea consultas SQL raw que contengan DDL
- Proporciona validación de bajo nivel para máxima seguridad

Esta arquitectura bicapa garantiza que las validaciones de freeze no puedan ser eludidas.

## Troubleshooting

### Problema: "No puedo crear tablas"

```php
// Verificar si el freeze está activo
if ($orm->isFrozen()) {
    echo "Freeze global está activo";
    $orm->freeze(false); // Desactivar si es necesario
}

if ($orm->isModelFrozen($modelClass)) {
    echo "El modelo específico está congelado";
    $orm->freezeModel($modelClass, false); // Desactivar para el modelo
}
```

### Problema: "Error en producción con DDL"

```php
// En producción, es normal que DDL esté bloqueado
// Para permitir migraciones, desactivar temporalmente:
$orm->freeze(false);
runMigrations();
$orm->freeze(true); // Reactivar después
```

### Problema: "Logs de violación demasiado frecuentes"

```php
// Revisar si hay código que inadvertidamente intenta DDL
// Usar el stack trace en los logs para identificar el origen
try {
    $orm->exec($suspiciousQuery);
} catch (VersaORMException $e) {
    error_log("Stack trace: " . $e->getTraceAsString());
}
```

## Conclusión

El modo freeze es una herramienta poderosa para proteger la integridad del esquema de base de datos en aplicaciones críticas. Su implementación bicapa (PHP + Rust) garantiza máxima seguridad, mientras que su flexibilidad permite un control granular según las necesidades de cada aplicación.

Úsalo sabiamente para:
- ✅ Proteger producción contra cambios accidentales
- ✅ Crear entornos de desarrollo controlados
- ✅ Cumplir con requisitos de auditoría y compliance
- ✅ Prevenir alteraciones no autorizadas del esquema
