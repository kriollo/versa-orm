<?php

declare(strict_types=1);

namespace App\Models;

use VersaORM\ErrorHandler;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaModel;
use VersaORM\VersaORMException;

use function defined;
use function in_array;

use const DIRECTORY_SEPARATOR;

/**
 * BaseModel - Clase base para todos los modelos de tu aplicación.
 *
 * Incluye manejo automático de errores y funcionalidades comunes.
 */
abstract class BaseModel extends VersaModel
{
    use HandlesErrors;

    // La configuración de errores se hereda del trait HandlesErrors

    /**
     * Inicialización del modelo.
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($this->table ?? 'default_table', static::getORM());

        // Llenar atributos si se proporcionaron
        if ($attributes !== []) {
            $this->fill($attributes);
        }

        // Configurar el manejo de errores para este modelo
        static::configureErrorHandling([
            'log_errors' => true,
            'throw_on_error' => false, // No lanzar excepciones por defecto
            'format_for_api' => true,  // Formatear para respuestas de API
            'include_suggestions' => true,
        ]);

        // El ErrorHandler ya está configurado automáticamente por VersaORM
        // Solo configurar debug mode si no está configurado
        if (!ErrorHandler::isConfigured()) {
            ErrorHandler::setDebugMode($this->isDebugMode());
        }
    }

    /**
     * Override de métodos principales con manejo de errores mejorado.
     */
    public function save(string $primaryKey = 'id'): array
    {
        return $this->executeWithLogging('save', function () use ($primaryKey): array {
            if (!$this->validateBeforeOperation('save')) {
                return [];
            }

            return parent::save($primaryKey);
        });
    }

    public function store(): void
    {
        $this->executeWithLogging('store', function (): void {
            if (!$this->validateBeforeOperation('store')) {
                return;
            }
            parent::store();
        });
    }

    public function update(array $attributes): self
    {
        return $this->executeWithLogging('update', function () use ($attributes): self|VersaModel {
            if (!$this->validateBeforeOperation('update')) {
                return $this;
            }

            return parent::update($attributes);
        }, ['update_data' => $attributes]);
    }

    public function delete(): void
    {
        $this->executeWithLogging('delete', function (): void {
            if (!$this->validateBeforeOperation('delete')) {
                return;
            }
            parent::delete();
        });
    }

    /**
     * Métodos de conveniencia para respuestas de API.
     */

    /**
     * Convierte el modelo a array para respuesta de API.
     */
    public function toApiResponse(): array
    {
        $response = [
            'success' => !$this->hasError(),
            'data' => $this->hasError() ? null : $this->toArray(),
        ];

        if ($this->hasError()) {
            $response['error'] = [
                'message' => $this->getLastErrorMessage(),
                'code' => $this->getLastErrorCode(),
                'suggestions' => $this->getLastErrorSuggestions(),
            ];
        }

        return $response;
    }

    /**
     * Respuesta de API para operaciones de creación.
     */
    public function createApiResponse(): array
    {
        if ($this->hasError()) {
            return [
                'success' => false,
                'message' => 'Failed to create record',
                'error' => [
                    'message' => $this->getLastErrorMessage(),
                    'code' => $this->getLastErrorCode(),
                    'suggestions' => $this->getLastErrorSuggestions(),
                ],
            ];
        }

        return [
            'success' => true,
            'message' => 'Record created successfully',
            'data' => $this->toArray(),
            'id' => $this->getAttribute('id'),
        ];
    }

    /**
     * Respuesta de API para operaciones de actualización.
     */
    public function updateApiResponse(): array
    {
        if ($this->hasError()) {
            return [
                'success' => false,
                'message' => 'Failed to update record',
                'error' => [
                    'message' => $this->getLastErrorMessage(),
                    'code' => $this->getLastErrorCode(),
                    'suggestions' => $this->getLastErrorSuggestions(),
                ],
            ];
        }

        return [
            'success' => true,
            'message' => 'Record updated successfully',
            'data' => $this->toArray(),
        ];
    }

    /**
     * Respuesta de API para operaciones de eliminación.
     */
    public function deleteApiResponse(): array
    {
        if ($this->hasError()) {
            return [
                'success' => false,
                'message' => 'Failed to delete record',
                'error' => [
                    'message' => $this->getLastErrorMessage(),
                    'code' => $this->getLastErrorCode(),
                    'suggestions' => $this->getLastErrorSuggestions(),
                ],
            ];
        }

        return [
            'success' => true,
            'message' => 'Record deleted successfully',
        ];
    }

    /**
     * Métodos estáticos con manejo de errores.
     */
    public static function findWithErrorHandling(int $id): ?static
    {
        try {
            return static::find($id);
        } catch (VersaORMException $e) {
            ErrorHandler::handleException($e, [
                'model_class' => static::class,
                'operation' => 'find',
                'id' => $id,
            ]);

            return null;
        }
    }

    public static function findAllWithErrorHandling(array $conditions = []): array
    {
        try {
            return static::findAll($conditions);
        } catch (VersaORMException $e) {
            ErrorHandler::handleException($e, [
                'model_class' => static::class,
                'operation' => 'findAll',
                'conditions' => $conditions,
            ]);

            return [];
        }
    }

    /**
     * Obtiene estadísticas de rendimiento del modelo.
     */
    public static function getPerformanceStats(): array
    {
        $errorStats = static::getErrorStats();

        return [
            'model_class' => static::class,
            'error_stats' => $errorStats,
            'memory_usage' => memory_get_usage(true),
            'peak_memory' => memory_get_peak_usage(true),
        ];
    }

    /**
     * Método para debugging - muestra información detallada del último error.
     */
    public function debugLastError(): void
    {
        if (!$this->hasError()) {
            echo "No errors found.\n";

            return;
        }

        $errorData = $this->getLastError();
        echo ErrorHandler::formatForDevelopment($errorData);
    }

    /**
     * Determina si estamos en modo debug.
     */
    protected function isDebugMode(): bool
    {
        // Puedes personalizar esto según tu framework
        return defined('APP_DEBUG') && APP_DEBUG === true;
    }

    /**
     * Método para operaciones de base de datos con logging automático.
     */
    protected function executeWithLogging(string $operation, callable $callback, array $context = [])
    {
        $startTime = microtime(true);

        try {
            $result = $this->withErrorHandling($callback, array_merge($context, [
                'operation' => $operation,
                'start_time' => $startTime,
            ]));

            // Log operación exitosa
            $this->logOperation($operation, true, microtime(true) - $startTime, $context);

            return $result;
        } catch (VersaORMException $e) {
            // Log operación fallida
            $this->logOperation($operation, false, microtime(true) - $startTime, $context, $e);

            throw $e;
        }
    }

    /**
     * Log de operaciones.
     */
    protected function logOperation(string $operation, bool $success, float $duration, array $context = [], ?VersaORMException $exception = null): void
    {
        $logData = [
            'model' => static::class,
            'table' => $this->getTable(),
            'operation' => $operation,
            'success' => $success,
            'duration_ms' => round($duration * 1000, 2),
            'timestamp' => date('Y-m-d H:i:s'),
            'context' => $context,
        ];

        if ($exception instanceof VersaORMException) {
            $logData['error'] = [
                'message' => $exception->getMessage(),
                'code' => $exception->getErrorCode(),
                'query' => $exception->getQuery(),
                'bindings' => $exception->getBindings(),
            ];
        }

        // Escribir al log configurado en VersaORM si está disponible
        $logPath = ErrorHandler::getLogPath();

        if ($logPath !== null && $logPath !== '' && $logPath !== '0') {
            $logFile = $logPath . DIRECTORY_SEPARATOR . 'versaorm_operations_' . date('Y-m-d') . '.log';
            $logLine = json_encode($logData, JSON_UNESCAPED_UNICODE) . PHP_EOL;
            file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
        } else {
            // Fallback al error_log del sistema
            error_log(json_encode($logData));
        }
    }

    /**
     * Valida el modelo antes de operaciones críticas.
     */
    protected function validateModel(): array
    {
        $errors = [];

        // Validaciones básicas
        if (in_array($this->getTable(), ['', '0'], true)) {
            $errors[] = 'Model table name is not defined';
        }

        // Validaciones personalizadas (override en modelos específicos)
        $customErrors = $this->customValidation();

        return array_merge($errors, $customErrors);
    }

    /**
     * Validaciones personalizadas (override en modelos específicos).
     */
    protected function customValidation(): array
    {
        return [];
    }
}
