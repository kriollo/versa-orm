# Sistema de Manejo de Errores de VersaORM

Este proporciona un manejo completo y detallado de errores para VersaORM, incluyendo información de contexto, sugerencias de solución, y integración fácil con tu framework.

## Características Principales

### 🔍 **Información Detallada de Errores**
- **Ubicación exacta**: Archivo, línea, y función donde ocurrió el error
- **Contexto del origen**: Modelo, controlador, o componente que causó el error
- **Query SQL**: La consulta que falló con parámetros formateados
- **Stack trace**: Completo en debug, simplificado en producción
- **Sugerencias**: Recomendaciones automáticas para resolver el error

### 🛡️ **Manejo Seguro**
- **Métodos seguros**: Versiones de métodos que no lanzan excepciones
- **Validación automática**: Validaciones antes de operaciones críticas
- **Logging automático**: Registro de todas las operaciones y errores
- **Modo debug/producción**: Información apropiada según el entorno

### 📊 **Estadísticas y Monitoreo**
- **Log de errores**: Historial de errores con contexto completo
- **Estadísticas por modelo**: Análisis de errores por tipo y frecuencia
- **Métricas de rendimiento**: Tiempo de ejecución y uso de memoria

## Estructura del Sistema

```
src/
├── ErrorHandler.php           # Clase principal de manejo de errores
├── Traits/HandlesErrors.php   # Trait para modelos
└── VersaORMException.php      # Excepción personalizada (ya existente)

example/
├── BaseModel.php              # Modelo base con manejo de errores
├── UserModel.php              # Ejemplo de modelo específico
├── UserController.php         # Ejemplo de controlador
└── usage_example.php          # Ejemplo completo de uso
```

## Uso Básico

### 1. Configuración Inicial

```php
use VersaORM\ErrorHandler;
use VersaORM\VersaORM;

// Configurar ErrorHandler
ErrorHandler::setDebugMode(true); // En desarrollo
ErrorHandler::setCustomHandler(function ($errorData) {
    // Tu lógica de logging personalizada
    Log::error('VersaORM Error', $errorData);
});

// Configurar VersaORM
$orm = new VersaORM($config);
YourModel::setORM($orm);
```

### 2. Crear un Modelo Base

```php
use VersaORM\VersaModel;
use VersaORM\Traits\HandlesErrors;

class BaseModel extends VersaModel
{
    use HandlesErrors;

    protected static array $errorConfig = [
        'log_errors' => true,
        'throw_on_error' => false,  // No lanzar excepciones por defecto
        'format_for_api' => true,   // Formatear para APIs
        'include_suggestions' => true,
    ];
}
```

### 3. Usar Métodos Seguros

```php
class UserModel extends BaseModel
{
    protected string $table = 'users';

    public function createUser(array $data): array
    {
        $this->fill($data);
        $result = $this->safeSave(); // No lanza excepciones

        if ($this->hasError()) {
            return [
                'success' => false,
                'message' => $this->getLastErrorMessage(),
                'code' => $this->getLastErrorCode(),
                'suggestions' => $this->getLastErrorSuggestions(),
            ];
        }

        return [
            'success' => true,
            'data' => $this->toArray(),
        ];
    }
}
```

## Métodos Disponibles

### ErrorHandler

```php
// Configuración
ErrorHandler::setDebugMode(bool $enabled);
ErrorHandler::setCustomHandler(callable $handler);

// Manejo de excepciones
$errorData = ErrorHandler::handleException(VersaORMException $e, array $context);

// Logging
$errors = ErrorHandler::getErrorLog();
ErrorHandler::clearErrorLog();

// Formateo
$devOutput = ErrorHandler::formatForDevelopment($errorData);
$prodOutput = ErrorHandler::formatForProduction($errorData);

// Wrapper automático
$result = ErrorHandler::wrap(function() {
    // Tu código que puede fallar
}, $context);
```

### Trait HandlesErrors

```php
// Métodos seguros (no lanzan excepciones)
$result = $model->safeSave();
$result = $model->safeUpdate($data);
$result = $model->safeDelete();
$result = $model->safeUpsert($uniqueKeys);

// Verificación de errores
if ($model->hasError()) {
    $message = $model->getLastErrorMessage();
    $code = $model->getLastErrorCode();
    $suggestions = $model->getLastErrorSuggestions();
}

// Estadísticas
$stats = YourModel::getErrorStats();

// Debug
$model->debugLastError();
```

### BaseModel (Ejemplo)

```php
// Respuestas de API
$response = $model->toApiResponse();
$response = $model->createApiResponse();
$response = $model->updateApiResponse();
$response = $model->deleteApiResponse();

// Métodos con logging automático
$result = $model->save();        // Con logging automático
$result = $model->update($data); // Con logging automático

// Estadísticas de rendimiento
$stats = YourModel::getPerformanceStats();
```

## Tipos de Errores y Códigos

### Códigos de Error Comunes

| Código | Descripción | Sugerencias Automáticas |
|--------|-------------|------------------------|
| `INVALID_IDENTIFIER` | Nombre de tabla/columna inválido | Verificar caracteres especiales, SQL injection |
| `MASS_ASSIGNMENT_ERROR` | Error de asignación masiva | Agregar campo a $fillable |
| `VALIDATION_ERROR` | Error de validación | Revisar reglas de validación |
| `NO_ORM_INSTANCE` | No hay instancia de ORM | Llamar VersaModel::setORM() |
| `PDO_ENGINE_FAILED` | Error de base de datos | Verificar conexión y SQL |
| `FREEZE_VIOLATION` | Modelo congelado | Llamar unfreeze() si es necesario |

### Información de Contexto

```php
$errorData = [
    'error' => [
        'type' => 'VersaORMException',
        'message' => 'Error message',
        'code' => 'ERROR_CODE',
        'file' => '/path/to/file.php',
        'line' => 123,
    ],
    'query' => [
        'sql' => 'SELECT * FROM users WHERE id = ?',
        'bindings' => [1],
        'formatted_sql' => 'SELECT * FROM users WHERE id = 1',
    ],
    'origin' => [
        'location' => 'application',
        'type' => 'model',
        'class' => 'App\\Models\\UserModel',
        'function' => 'save',
    ],
    'suggestions' => [
        'Check database connection',
        'Verify table exists',
    ],
    'context' => [
        'model_class' => 'UserModel',
        'operation' => 'save',
        'timestamp' => '2025-08-12 19:30:00',
    ],
];
```

## Integración con Frameworks

### Laravel

```php
// En tu ServiceProvider
public function boot()
{
    ErrorHandler::setDebugMode(config('app.debug'));
    ErrorHandler::setCustomHandler(function ($errorData) {
        Log::channel('database')->error('VersaORM Error', $errorData);
    });
}

// En tu modelo
class User extends BaseModel
{
    // Tu código...
}
```

### Symfony

```php
// En tu servicio
class VersaORMErrorService
{
    public function __construct(LoggerInterface $logger)
    {
        ErrorHandler::setCustomHandler(function ($errorData) use ($logger) {
            $logger->error('VersaORM Error', $errorData);
        });
    }
}
```

### API REST

```php
class ApiController
{
    public function handleRequest()
    {
        try {
            $result = $this->model->safeSave();

            return response()->json([
                'success' => !$this->model->hasError(),
                'data' => $this->model->hasError() ? null : $this->model->toArray(),
                'error' => $this->model->hasError() ? [
                    'message' => $this->model->getLastErrorMessage(),
                    'code' => $this->model->getLastErrorCode(),
                    'suggestions' => $this->model->getLastErrorSuggestions(),
                ] : null,
            ]);

        } catch (VersaORMException $e) {
            $errorData = ErrorHandler::handleException($e);

            return response()->json([
                'success' => false,
                'error' => ErrorHandler::formatForProduction($errorData),
            ], 500);
        }
    }
}
```

## Mejores Prácticas

### 1. **Configuración por Entorno**
```php
// Desarrollo
ErrorHandler::setDebugMode(true);
BaseModel::configureErrorHandling([
    'throw_on_error' => false,
    'include_suggestions' => true,
]);

// Producción
ErrorHandler::setDebugMode(false);
BaseModel::configureErrorHandling([
    'throw_on_error' => false,
    'format_for_api' => true,
    'include_suggestions' => false,
]);
```

### 2. **Logging Estructurado**
```php
ErrorHandler::setCustomHandler(function ($errorData) {
    Log::error('database_error', [
        'error_code' => $errorData['error']['error_code'],
        'model' => $errorData['context']['model_class'] ?? 'unknown',
        'operation' => $errorData['context']['operation'] ?? 'unknown',
        'query' => $errorData['query']['sql'],
        'suggestions' => $errorData['suggestions'],
        'timestamp' => $errorData['context']['timestamp'],
    ]);
});
```

### 3. **Monitoreo y Alertas**
```php
// Alertar en errores críticos
ErrorHandler::setCustomHandler(function ($errorData) {
    $criticalErrors = ['PDO_ENGINE_FAILED', 'CONNECTION_FAILED'];

    if (in_array($errorData['error']['error_code'], $criticalErrors)) {
        // Enviar alerta (Slack, email, etc.)
        AlertService::send('Critical database error', $errorData);
    }
});
```

### 4. **Validación Preventiva**
```php
class UserModel extends BaseModel
{
    protected function customValidation(): array
    {
        $errors = [];

        if (isset($this->attributes['email'])) {
            if (!filter_var($this->attributes['email'], FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Invalid email format';
            }

            if ($this->emailExists($this->attributes['email'])) {
                $errors[] = 'Email already exists';
            }
        }

        return $errors;
    }
}
```

## Ejemplo Completo

Ejecuta `php example/usage_example.php` para ver una demostración completa del sistema en acción.

## Contribuir

Para contribuir al sistema de manejo de errores:

1. Agrega nuevos códigos de error en `generateSuggestions()`
2. Mejora la detección de origen en `findOriginLocation()`
3. Añade nuevas validaciones en los modelos base
4. Extiende el formateo para diferentes entornos

## Soporte

Para reportar problemas o sugerir mejoras, crea un issue en el repositorio principal de VersaORM.
