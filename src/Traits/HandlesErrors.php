<?php

declare(strict_types=1);

namespace VersaORM\Traits;

use VersaORM\ErrorHandler;
use VersaORM\VersaORMException;

use function array_slice;
use function count;

/**
 * HandlesErrors - Trait para manejo automático de errores en modelos.
 *
 * Este trait proporciona métodos para capturar y manejar errores de VersaORM
 * de manera consistente en todos los modelos.
 *
 * @phpstan-ignore-next-line
 */
trait HandlesErrors
{
    /**
     * Configuración de manejo de errores para este modelo.
     */
    protected static array $errorConfig = [
        'log_errors' => true,
        'throw_on_error' => true,
        'format_for_api' => false,
        'include_suggestions' => true,
    ];

    /**
     * Último error capturado.
     */
    protected null|array $lastError = null;

    /**
     * Configura el manejo de errores para este modelo.
     */
    public static function configureErrorHandling(array $config): void
    {
        static::$errorConfig = array_merge(static::$errorConfig, $config);
    }

    /**
     * Obtiene el último error ocurrido.
     */
    public function getLastError(): null|array
    {
        return $this->lastError;
    }

    /**
     * Verifica si hubo un error en la última operación.
     */
    public function hasError(): bool
    {
        return $this->lastError !== null;
    }

    /**
     * Obtiene el mensaje del último error.
     */
    public function getLastErrorMessage(): null|string
    {
        return $this->lastError['error']['message'] ?? null;
    }

    /**
     * Obtiene el código del último error.
     */
    public function getLastErrorCode(): null|string
    {
        return $this->lastError['error']['error_code'] ?? null;
    }

    /**
     * Obtiene sugerencias para resolver el último error.
     */
    public function getLastErrorSuggestions(): array
    {
        return $this->lastError['suggestions'] ?? [];
    }

    /**
     * Métodos seguros que capturan errores automáticamente.
     */

    /**
     * Save seguro con manejo de errores.
     */
    public function safeSave(): mixed
    {
        return $this->withErrorHandling($this->save(...), ['operation' => 'save']);
    }

    /**
     * Store seguro con manejo de errores.
     */
    public function safeStore(): mixed
    {
        return $this->withErrorHandling($this->store(...), ['operation' => 'store']);
    }

    /**
     * Update seguro con manejo de errores.
     */
    public function safeUpdate(array $data): mixed
    {
        return $this->withErrorHandling(fn() => $this->update($data), ['operation' => 'update', 'data' => $data]);
    }

    /**
     * Delete seguro con manejo de errores.
     */
    public function safeDelete(): mixed
    {
        return $this->withErrorHandling($this->delete(...), ['operation' => 'delete']);
    }

    /**
     * Upsert seguro con manejo de errores.
     */
    public function safeUpsert(array $uniqueKeys, array $updateColumns = []): mixed
    {
        return $this->withErrorHandling(fn() => $this->upsert($uniqueKeys, $updateColumns), [
            'operation' => 'upsert',
            'unique_keys' => $uniqueKeys,
        ]);
    }

    /**
     * Find seguro con manejo de errores.
     */
    public static function safeFind(mixed $id): mixed
    {
        return static::withStaticErrorHandling(static fn() => static::find($id), ['operation' => 'find', 'id' => $id]);
    }

    /**
     * FindAll seguro con manejo de errores.
     */
    public static function safeFindAll(array $conditions = []): mixed
    {
        return static::withStaticErrorHandling(static fn() => static::findAll($conditions), [
            'operation' => 'findAll',
            'conditions' => $conditions,
        ]);
    }

    /**
     * Obtiene estadísticas de errores para este modelo.
     */
    public static function getErrorStats(): array
    {
        $allErrors = ErrorHandler::getErrorLog();
        $modelErrors = array_filter(
            $allErrors,
            static fn($error): bool => ($error['context']['model_class'] ?? '') === static::class,
        );

        $stats = [
            'total_errors' => count($modelErrors),
            'error_types' => [],
            'most_common_errors' => [],
            'recent_errors' => array_slice($modelErrors, -5),
        ];

        // Contar tipos de errores
        foreach ($modelErrors as $error) {
            $errorCode = $error['error']['error_code'];
            $stats['error_types'][$errorCode] = ($stats['error_types'][$errorCode] ?? 0) + 1;
        }

        // Ordenar por frecuencia
        arsort($stats['error_types']);
        $stats['most_common_errors'] = array_slice($stats['error_types'], 0, 5, true);

        return $stats;
    }

    /**
     * Ejecuta una operación con manejo automático de errores.
     */
    protected function withErrorHandling(callable $operation, array $context = [])
    {
        try {
            $this->lastError = null;

            return $operation();
        } catch (VersaORMException $e) {
            return $this->handleModelError($e, $context);
        }
    }

    /**
     * Maneja un error específico del modelo.
     */
    protected function handleModelError(VersaORMException $exception, array $context = []): mixed
    {
        // Agregar contexto del modelo
        $modelContext = array_merge($context, [
            'model_class' => static::class,
            'model_table' => $this->getTable() ?? 'unknown',
            'model_attributes' => $this->attributes ?? [],
            'operation_context' => debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3),
        ]);

        // Procesar el error
        $errorData = ErrorHandler::handleException($exception, $modelContext);
        $this->lastError = $errorData;

        // Decidir qué hacer basado en la configuración
        if (static::$errorConfig['throw_on_error']) {
            throw $exception;
        }

        // Retornar formato apropiado
        if (static::$errorConfig['format_for_api']) {
            return $this->formatErrorForApi($errorData);
        }

        return null;
    }

    /**
     * Formatea el error para respuesta de API.
     */
    protected function formatErrorForApi(array $errorData): array
    {
        $response = [
            'success' => false,
            'error' => [
                'message' => $errorData['error']['message'],
                'code' => $errorData['error']['error_code'],
                'type' => 'database_error',
            ],
        ];

        if (static::$errorConfig['include_suggestions']) {
            $response['error']['suggestions'] = $errorData['suggestions'];
        }

        // En modo debug, incluir más información
        if (ErrorHandler::isDebugMode()) {
            $response['debug'] = [
                'query' => $errorData['query'],
                'origin' => $errorData['origin'],
                'context' => $errorData['context'],
            ];
        }

        return $response;
    }

    /**
     * Manejo de errores para métodos estáticos.
     */
    protected static function withStaticErrorHandling(callable $operation, array $context = []): mixed
    {
        try {
            return $operation();
        } catch (VersaORMException $e) {
            $modelContext = array_merge($context, [
                'model_class' => static::class,
                'static_operation' => true,
            ]);

            $errorData = ErrorHandler::handleException($e, $modelContext);

            if (static::$errorConfig['throw_on_error']) {
                throw $e;
            }

            return null;
        }
    }

    /**
     * Valida datos antes de operaciones críticas.
     */
    protected function validateBeforeOperation(string $operation): bool
    {
        try {
            switch ($operation) {
                case 'save':
                case 'store':
                    if (empty($this->attributes)) {
                        throw new VersaORMException('Cannot save model with empty attributes', 'EMPTY_ATTRIBUTES');
                    }
                    break;

                case 'update':
                    if (!$this->exists()) {
                        throw new VersaORMException(
                            'Cannot update model that does not exist in database',
                            'MODEL_NOT_EXISTS',
                        );
                    }
                    break;

                case 'delete':
                    if (!$this->exists()) {
                        throw new VersaORMException(
                            'Cannot delete model that does not exist in database',
                            'MODEL_NOT_EXISTS',
                        );
                    }
                    break;
            }

            return true;
        } catch (VersaORMException $e) {
            $this->handleModelError($e, ['validation_operation' => $operation]);

            return false;
        }
    }

    /**
     * Verifica si el modelo existe en la base de datos.
     */
    protected function exists(): bool
    {
        if (!isset($this->attributes['id'])) {
            return false;
        }

        try {
            $result = static::find($this->attributes['id']);

            return $result !== null;
        } catch (VersaORMException) {
            return false;
        }
    }
}
