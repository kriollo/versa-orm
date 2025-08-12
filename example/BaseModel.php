<?php

declare(strict_types=1);

namespace App\Models;

use VersaORM\VersaModel;
use VersaORM\Traits\HandlesErrors;
use VersaORM\ErrorHandler;
use VersaORM\VersaORMException;

/**
 * BaseModel - Clase base para todos los modelos de tu aplicación
 *
 * Incluye manejo automático de errores y funcionalidades comunes.
 */
abstract class BaseModel extends VersaModel
{
    use HandlesErrors;

    /**
     * Configuración de errores por defecto para todos los modelos
     */
    protected static array $errorConfig = [
        'log_errors' => true,
        'throw_on_error' => false, // No lanzar excepciones por defecto
        'format_for_api' => true,  // Formatear para respuestas de API
        'include_suggestions' => true,
    ];

    /**
     * Inicialización del modelo
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        // Configurar ErrorHandler si no está configurado
        if (!ErrorHandler::isConfigured()) {
            ErrorHandler::setDebugMode($this->isDebugMode());
        }
    }

    /**
     * Determina si estamos en modo debug
     */
    protected function isDebugMode(): bool
    {
        // Puedes personalizar esto según tu framework
        return defined('APP_DEBUG') && APP_DEBUG === true;
    }

    /**
     * Método para operaciones de base de datos con logging automático
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
     * Log de operaciones
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

        if ($exception) {
            $logData['error'] = [
                'message' => $exception->getMessage(),
                'code' => $exception->getErrorCode(),
                'query' => $exception->getQuery(),
                'bindings' => $exception->getBindings(),
            ];
        }

        // Aquí puedes integrar con tu sistema de logging
        // Por ejemplo: Log::info('database_operation', $logData);
        error_log(json_encode($logData));
    }

    /**
     * Override de métodos principales con manejo de errores mejorado
     */

    public function save(): mixed
    {
        return $this->executeWithLogging('save', function () {
            if (!$this->validateBeforeOperation('save')) {
                return false;
            }
            return parent::save();
        });
    }

    public function store(): mixed
    {
        return $this->executeWithLogging('store', function () {
            if (!$this->validateBeforeOperation('store')) {
                return false;
            }
            return parent::store();
        });
    }

    public function update(array $data): mixed
    {
        return $this->executeWithLogging('update', function () use ($data) {
            if (!$this->validateBeforeOperation('update')) {
                return false;
            }
            return parent::update($data);
        }, ['update_data' => $data]);
    }

    public function delete(): mixed
    {
        return $this->executeWithLogging('delete', function () {
            if (!$this->validateBeforeOperation('delete')) {
                return false;
            }
            return parent::delete();
        });
    }

    /**
     * Métodos de conveniencia para respuestas de API
     */

    /**
     * Convierte el modelo a array para respuesta de API
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
     * Respuesta de API para operaciones de creación
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
     * Respuesta de API para operaciones de actualización
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
     * Respuesta de API para operaciones de eliminación
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
     * Métodos estáticos con manejo de errores
     */

    public static function findWithErrorHandling($id): ?static
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
     * Obtiene estadísticas de rendimiento del modelo
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
     * Método para debugging - muestra información detallada del último error
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
     * Valida el modelo antes de operaciones críticas
     */
    protected function validateModel(): array
    {
        $errors = [];

        // Validaciones básicas
        if (empty($this->getTable())) {
            $errors[] = 'Model table name is not defined';
        }

        // Validaciones personalizadas (override en modelos específicos)
        $customErrors = $this->customValidation();
        $errors = array_merge($errors, $customErrors);

        return $errors;
    }

    /**
     * Validaciones personalizadas (override en modelos específicos)
     */
    protected function customValidation(): array
    {
        return [];
    }
}
