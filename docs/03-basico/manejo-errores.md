# Manejo de Errores con VersaORM

El manejo adecuado de errores es crucial para crear aplicaciones robustas. VeM proporciona un sistema de excepciones claro y específico que te ayuda a identificar y resolver problemas rápidamente.

## VersaORMException: La excepción principal

VersaORM utiliza `VersaORMException` como su excepción principal. Esta clase extiende la excepción estándar de PHP y proporciona información detallada sobre errores específicos del ORM.

### Estructura básica de manejo de errores

```php
<?php
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

try {
    $orm = new VersaORM([
        'host' => 'localhost',
        'database' => 'mi_app',
        'username' => 'usuario',
        'password' => 'contraseña',
        'driver' => 'mysql'
    ]);

    // Operaciones con VersaORM
    $user = VersaModel::dispense('users');
    $user->email = 'test@ejemplo.com';
    $user->store();

} catch (VersaORMException $e) {
    echo "Error de VersaORM: " . $e->getMessage();
    echo "Código de error: " . $e->getCode();
} catch (Exception $e) {
    echo "Error general: " . $e->getMessage();
}
```

## Tipos de errores comunes

### 1. Errores de conexión a la base de datos

```php
try {
    $orm = new VersaORM([
        'host' => 'servidor_inexistente',
        'database' => 'mi_app',
        'username' => 'usuario',
        'password' => 'contraseña_incorrecta',
        'driver' => 'mysql'
    ]);

} catch (VersaORMException $e) {
    echo "Error de conexión: " . $e->getMessage();

    // Ejemplos de mensajes comunes:
    // - "Connection failed: Access denied for user"
    // - "Connection failed: Unknown database"
    // - "Connection failed: Can't connect to MySQL server"
}
```

**Soluciones comunes:**

- Verificar credenciales de base de datos
- Confirmar que el servidor de BD esté ejecutándose
- Revisar configuración de firewall/red

### 2. Errores de tabla inexistente

```php
try {
    $user = VersaModel::dispense('non_existent_table');
    $user->name = 'Test';
    $user->store();

} catch (VersaORMException $e) {
    echo "Error de tabla: " . $e->getMessage();
    // "Table 'mi_app.non_existent_table' doesn't exist"

    // Crear la tabla automáticamente si es necesario
    if (strpos($e->getMessage(), "doesn't exist") !== false) {
        echo "La tabla no existe. Creando automáticamente...";
        // VersaORM puede crear tablas automáticamente en modo desarrollo
    }
}
```

### 3. Errores de restricciones de base de datos

```php
try {
    // Intentar insertar email duplicado
    $user1 = VersaModel::dispense('users');
    $user1->email = 'duplicado@ejemplo.com';
    $user1->store();

    $user2 = VersaModel::dispense('users');
    $user2->email = 'duplicado@ejemplo.com'; // Email duplicado
    $user2->store();

} catch (VersaORMException $e) {
    if (strpos($e->getMessage(), 'Duplicate entry') !== false) {
        echo "Error: El email ya está registrado";
    } elseif (strpos($e->getMessage(), 'foreign key constraint') !== false) {
        echo "Error: Referencia a registro inexistente";
    } else {
        echo "Error de restricción: " . $e->getMessage();
    }
}
```

### 4. Errores de validación de datos

```php
try {
    $user = VersaModel::dispense('users');
    $user->email = 'email_invalido'; // Email sin formato válido
    $user->age = -5; // Edad negativa

    // Si tienes validaciones personalizadas
    if (!filter_var($user->email, FILTER_VALIDATE_EMAIL)) {
        throw new VersaORMException('Email inválido: ' . $user->email);
    }

    if ($user->age < 0) {
        throw new VersaORMException('La edad no puede ser negativa');
    }

    $user->store();

} catch (VersaORMException $e) {
    echo "Error de validación: " . $e->getMessage();
}
```

## Manejo específico por tipo de operación

### Errores en CREATE (dispense/store)

```php
function createUser($orm, $data) {
    try {
        $user = VersaModel::dispense('users');

        // Validar datos requeridos
        if (empty($data['name'])) {
            throw new VersaORMException('El nombre es requerido');
        }

        if (empty($data['email'])) {
            throw new VersaORMException('El email es requerido');
        }

        // Verificar email único
        $emailExists = VersaModel::findOne('users', 'email = ?', [$data['email']]);
        if ($emailExists !== null) {
            throw new VersaORMException('El email ya está registrado');
        }

        $user->name = $data['name'];
        $user->email = $data['email'];
        $user->active = $data['active'] ?? true;

        $id = $user->store();
        return ['success' => true, 'id' => $id];

    } catch (VersaORMException $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

// Uso
$resultado = createUser($orm, [
    'name' => 'Juan Pérez',
    'email' => 'juan@ejemplo.com'
]);

if ($resultado['success']) {
    echo "Usuario creado con ID: " . $resultado['id'];
} else {
    echo "Error: " . $resultado['error'];
}
```

### Errores en READ (load/find)

```php
function getUser($orm, $id) {
    try {
        if (!is_numeric($id) || $id <= 0) {
            throw new VersaORMException('ID inválido: debe ser un número positivo');
        }

        $user = VersaModel::load('users', $id);

        if ($user === null) {
            throw new VersaORMException('Usuario no encontrado con ID: ' . $id);
        }

        return ['success' => true, 'user' => $user];

    } catch (VersaORMException $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

// Uso
$resultado = getUser($orm, 999);

if ($resultado['success']) {
    echo "Usuario: " . $resultado['user']->name;
} else {
    echo "Error: " . $resultado['error'];
}
```

### Errores en UPDATE (store)

```php
function updateUser($orm, $id, $data) {
    try {
        $user = VersaModel::load('users', $id);

        if ($user === null) {
            throw new VersaORMException('Usuario no encontrado para actualizar');
        }

        // Validar email único si se está cambiando
        if (isset($data['email']) && $data['email'] !== $user->email) {
            $emailExists = VersaModel::findOne('users', 'email = ? AND id != ?',
                [$data['email'], $id]);

            if ($emailExists !== null) {
                throw new VersaORMException('El email ya está en uso por otro usuario');
            }
        }

        // Actualizar solo campos proporcionados
        foreach ($data as $campo => $valor) {
            if (in_array($campo, ['name', 'email', 'active'])) {
                $user->$campo = $valor;
            }
        }

        $user->store();
        return ['success' => true, 'message' => 'Usuario actualizado'];

    } catch (VersaORMException $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

// Uso
$resultado = updateUser($orm, 1, [
    'name' => 'Juan Carlos Pérez',
    'email' => 'juancarlos@ejemplo.com'
]);

if ($resultado['success']) {
    echo $resultado['message'];
} else {
    echo "Error: " . $resultado['error'];
}
```

### Errores en DELETE (trash)

```php
function deleteUser($orm, $id) {
    try {
        $user = VersaModel::load('users', $id);

        if ($user === null) {
            throw new VersaORMException('Usuario no encontrado para eliminar');
        }

        // Verificar si tiene registros relacionados
        $posts = VersaModel::findAll('posts', 'user_id = ?', [$id]);
        if (count($posts) > 0) {
            throw new VersaORMException(
                'No se puede eliminar: el usuario tiene ' . count($posts) . ' posts asociados'
            );
        }

        $user->trash();
        return ['success' => true, 'message' => 'Usuario eliminado'];

    } catch (VersaORMException $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

// Uso
$resultado = deleteUser($orm, 1);

if ($resultado['success']) {
    echo $resultado['message'];
} else {
    echo "Error: " . $resultado['error'];
}
```

## Logging de errores

### Configurar logging básico

```php
function logError($message, $context = []) {
    $timestamp = date('Y-m-d H:i:s');
    $contextStr = !empty($context) ? json_encode($context) : '';
    $logMessage = "[$timestamp] ERROR: $message $contextStr\n";

    file_put_contents('logs/versaorm_errors.log', $logMessage, FILE_APPEND);
}

try {
    $user = VersaModel::dispense('users');
    $user->email = 'test@ejemplo.com';
    $user->store();

} catch (VersaORMException $e) {
    logError($e->getMessage(), [
        'file' => $e->getFile(),
        'line' => $e->getLine(),
        'trace' => $e->getTraceAsString()
    ]);

    echo "Error registrado. Contacte al administrador.";
}
```

### Logging avanzado con contexto

```php
class VersaORMLogger {
    private $logFile;

    public function __construct($logFile = 'logs/versaorm.log') {
        $this->logFile = $logFile;

        // Crear directorio si no existe
        $dir = dirname($logFile);
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }
    }

    public function logError(VersaORMException $e, $operation = '', $data = []) {
        $logEntry = [
            'timestamp' => date('c'),
            'level' => 'ERROR',
            'operation' => $operation,
            'message' => $e->getMessage(),
            'code' => $e->getCode(),
            'file' => $e->getFile(),
            'line' => $e->getLine(),
            'data' => $data
        ];

        file_put_contents($this->logFile, json_encode($logEntry) . "\n", FILE_APPEND);
    }

    public function logInfo($message, $data = []) {
        $logEntry = [
            'timestamp' => date('c'),
            'level' => 'INFO',
            'message' => $message,
            'data' => $data
        ];

        file_put_contents($this->logFile, json_encode($logEntry) . "\n", FILE_APPEND);
    }
}

// Uso
$logger = new VersaORMLogger();

try {
    $user = VersaModel::dispense('users');
    $user->name = 'Test User';
    $id = $user->store();

    $logger->logInfo('Usuario creado exitosamente', ['id' => $id]);

} catch (VersaORMException $e) {
    $logger->logError($e, 'CREATE_USER', ['name' => 'Test User']);
    echo "Error al crear usuario. Revise los logs.";
}
```

## Manejo de errores en transacciones

```php
function transferirDatos($orm, $fromId, $toId, $amount) {
    $orm->begin();

    try {
        // Cargar cuentas
        $fromAccount = VersaModel::load('accounts', $fromId);
        $toAccount = VersaModel::load('accounts', $toId);

        if ($fromAccount === null) {
            throw new VersaORMException('Cuenta origen no encontrada');
        }

        if ($toAccount === null) {
            throw new VersaORMException('Cuenta destino no encontrada');
        }

        if ($fromAccount->balance < $amount) {
            throw new VersaORMException('Saldo insuficiente');
        }

        // Realizar transferencia
        $fromAccount->balance -= $amount;
        $toAccount->balance += $amount;

        $fromAccount->store();
        $toAccount->store();

        // Registrar transacción
        $transaction = VersaModel::dispense('transactions');
        $transaction->from_account_id = $fromId;
        $transaction->to_account_id = $toId;
        $transaction->amount = $amount;
        $transaction->created_at = date('Y-m-d H:i:s');
        $transaction->store();

        $orm->commit();
        return ['success' => true, 'message' => 'Transferencia completada'];

    } catch (VersaORMException $e) {
        $orm->rollback();
        return ['success' => false, 'error' => $e->getMessage()];
    } catch (Exception $e) {
        $orm->rollback();
        return ['success' => false, 'error' => 'Error inesperado: ' . $e->getMessage()];
    }
}
```

## Ejemplo completo: Sistema robusto de manejo de errores

```php
<?php
require_once 'vendor/autoload.php';

use VersaORM\VersaORM;
use VersaORM\VersaORMException;

class UserManager {
    private $orm;
    private $logger;

    public function __construct($config) {
        try {
            $this->orm = new VersaORM($config);
            $this->logger = new VersaORMLogger();
        } catch (VersaORMException $e) {
            throw new Exception('Error de configuración: ' . $e->getMessage());
        }
    }

    public function createUser($data) {
        try {
            // Validaciones
            $this->validateUserData($data);

            // Verificar email único
            $existing = $this->orm->findOne('users', 'email = ?', [$data['email']]);
            if ($existing !== null) {
                throw new VersaORMException('Email ya registrado: ' . $data['email']);
            }

            // Crear usuario
            $user = $this->orm->dispense('users');
            $user->name = $data['name'];
            $user->email = $data['email'];
            $user->active = $data['active'] ?? true;
            $user->created_at = date('Y-m-d H:i:s');

            $id = $this->orm->store($user);

            $this->logger->logInfo('Usuario creado', ['id' => $id, 'email' => $data['email']]);

            return [
                'success' => true,
                'id' => $id,
                'message' => 'Usuario creado exitosamente'
            ];

        } catch (VersaORMException $e) {
            $this->logger->logError($e, 'CREATE_USER', $data);
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'code' => 'VERSAORM_ERROR'
            ];
        } catch (Exception $e) {
            $this->logger->logError(new VersaORMException($e->getMessage()), 'CREATE_USER', $data);
            return [
                'success' => false,
                'error' => 'Error interno del sistema',
                'code' => 'SYSTEM_ERROR'
            ];
        }
    }

    private function validateUserData($data) {
        if (empty($data['name'])) {
            throw new VersaORMException('El nombre es requerido');
        }

        if (empty($data['email'])) {
            throw new VersaORMException('El email es requerido');
        }

        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            throw new VersaORMException('Formato de email inválido');
        }

        if (strlen($data['name']) < 2) {
            throw new VersaORMException('El nombre debe tener al menos 2 caracteres');
        }
    }

    public function getUser($id) {
        try {
            if (!is_numeric($id) || $id <= 0) {
                throw new VersaORMException('ID inválido');
            }

            $user = $this->orm->load('users', $id);

            if ($user === null) {
                throw new VersaORMException('Usuario no encontrado');
            }

            return [
                'success' => true,
                'user' => $user->export()
            ];

        } catch (VersaORMException $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}

// Uso del sistema
try {
    $userManager = new UserManager([
        'host' => 'localhost',
        'database' => 'mi_app',
        'username' => 'usuario',
        'password' => 'contraseña',
        'driver' => 'mysql'
    ]);

    // Crear usuario
    $result = $userManager->createUser([
        'name' => 'Ana García',
        'email' => 'ana@ejemplo.com'
    ]);

    if ($result['success']) {
        echo "✅ " . $result['message'] . " (ID: " . $result['id'] . ")\n";

        // Obtener usuario
        $userResult = $userManager->getUser($result['id']);
        if ($userResult['success']) {
            echo "Usuario: " . $userResult['user']['name'] . "\n";
        }
    } else {
        echo "❌ Error: " . $result['error'] . "\n";
    }

} catch (Exception $e) {
    echo "💥 Error crítico: " . $e->getMessage() . "\n";
}
```

## Mejores prácticas para manejo de errores

### 1. Siempre usar try-catch con VersaORM

```php
// ✅ Correcto
try {
    $user->store();
} catch (VersaORMException $e) {
    // Manejar error específico
}

// ❌ Incorrecto
$user->store(); // Puede fallar sin aviso
```

### 2. Validar datos antes de operaciones

```php
// ✅ Correcto
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    throw new VersaORMException('Email inválido');
}

// ❌ Incorrecto
$user->email = $email; // Sin validación
```

### 3. Proporcionar mensajes de error útiles

```php
// ✅ Correcto
throw new VersaORMException('Email ya registrado: ' . $email);

// ❌ Incorrecto
throw new VersaORMException('Error');
```

### 4. Usar logging para debugging

```php
// ✅ Correcto
catch (VersaORMException $e) {
    error_log('VersaORM Error: ' . $e->getMessage());
    return 'Error interno';
}
```

## Próximos pasos

Ahora que sabes manejar errores en VersaORM, puedes continuar con:

- [Query Builder](../04-query-builder/README.md) - Para consultas más complejas
- [Relaciones](../05-relaciones/README.md) - Trabajar con múltiples tablas
- [Funcionalidades Avanzadas](../06-avanzado/README.md) - Transacciones y operaciones batch

```

```
