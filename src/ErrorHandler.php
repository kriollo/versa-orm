<?php

declare(strict_types=1);

namespace VersaORM;

use Exception;
use Throwable;

/**
 * ErrorHandler - Maneja y formatea errores detallados de VersaORM
 *
 * Esta clase proporciona métodos para capturar, formatear y reportar errores
 * detallados que ocurren en VersaORM, incluyendo información de contexto,
 * stack traces, y sugerencias de solución.
 */
class ErrorHandler
{
    private static bool $debugMode = false;
    private static array $errorLog = [];
    private static $customHandler = null;
    private static array $config = [];
    private static ?string $logPath = null;

    /**
     * Configura el modo debug
     */
    public static function setDebugMode(bool $enabled): void
    {
        self::$debugMode = $enabled;
    }

    /**
     * Establece un handler personalizado para errores
     */
    public static function setCustomHandler($handler): void
    {
        self::$customHandler = $handler;
    }

    /**
     * Configura el ErrorHandler desde la configuración de VersaORM
     */
    public static function configureFromVersaORM(array $config): void
    {
        self::$config = $config;

        // Configurar log path
        if (isset($config['log_path'])) {
            self::$logPath = rtrim($config['log_path'], '/\\');
        }

        // Configurar debug mode desde la config
        if (isset($config['debug'])) {
            self::$debugMode = (bool) $config['debug'];
        }

        // Crear directorio de logs si no existe
        if (self::$logPath && !is_dir(self::$logPath)) {
            mkdir(self::$logPath, 0755, true);
        }
    }

    /**
     * Obtiene el path de logs configurado
     */
    public static function getLogPath(): ?string
    {
        return self::$logPath;
    }

    /**
     * Verifica si el ErrorHandler está configurado
     */
    public static function isConfigured(): bool
    {
        return !empty(self::$config);
    }

    /**
     * Verifica si está en modo debug
     */
    public static function isDebugMode(): bool
    {
        return self::$debugMode;
    }

    /**
     * Captura y procesa una excepción de VersaORM
     */
    public static function handleException(VersaORMException $exception, array $context = []): array
    {
        $errorData = self::extractErrorData($exception, $context);

        // Log del error
        self::logError($errorData);

        // Llamar handler personalizado si existe
        if (self::$customHandler) {
            call_user_func(self::$customHandler, $errorData);
        }

        return $errorData;
    }

    /**
     * Extrae información detallada de la excepción
     */
    private static function extractErrorData(VersaORMException $exception, array $context = []): array
    {
        $trace = $exception->getTrace();
        $originInfo = self::findOriginLocation($trace);

        $errorData = [
            'error' => [
                'type' => 'VersaORMException',
                'message' => $exception->getMessage(),
                'code' => $exception->getCode(),
                'error_code' => $exception->getErrorCode(),
                'sql_state' => $exception->getSqlState(),
                'file' => $exception->getFile(),
                'line' => $exception->getLine(),
            ],
            'query' => [
                'sql' => $exception->getQuery(),
                'bindings' => $exception->getBindings(),
                'formatted_sql' => self::formatQuery($exception->getQuery(), $exception->getBindings()),
            ],
            'context' => array_merge($context, [
                'timestamp' => date('Y-m-d H:i:s'),
                'php_version' => PHP_VERSION,
                'memory_usage' => memory_get_usage(true),
                'peak_memory' => memory_get_peak_usage(true),
            ]),
            'origin' => $originInfo,
            'details' => $exception->getErrorDetails(),
            'stack_trace' => self::$debugMode ? $trace : self::getSimplifiedTrace($trace),
            'suggestions' => self::generateSuggestions($exception),
        ];

        return $errorData;
    }

    /**
     * Encuentra la ubicación de origen del error (modelo, controlador, etc.)
     */
    private static function findOriginLocation(array $trace): array
    {
        $origin = [
            'location' => 'unknown',
            'type' => 'unknown',
            'file' => null,
            'line' => null,
            'function' => null,
            'class' => null,
        ];

        foreach ($trace as $frame) {
            $file = $frame['file'] ?? '';
            $class = $frame['class'] ?? '';
            $function = $frame['function'] ?? '';

            // Buscar el primer frame que no sea de VersaORM interno
            if (!str_contains($file, 'VersaORM') && !str_contains($file, 'vendor')) {
                $origin['location'] = 'application';
                $origin['file'] = $file;
                $origin['line'] = $frame['line'] ?? null;
                $origin['function'] = $function;
                $origin['class'] = $class;

                // Determinar el tipo de origen
                if (str_contains($class, 'Model') || str_contains($file, 'Model')) {
                    $origin['type'] = 'model';
                } elseif (str_contains($class, 'Controller') || str_contains($file, 'Controller')) {
                    $origin['type'] = 'controller';
                } elseif (str_contains($class, 'Service') || str_contains($file, 'Service')) {
                    $origin['type'] = 'service';
                } else {
                    $origin['type'] = 'application';
                }
                break;
            }

            // Si es de VersaORM, determinar el componente
            if (str_contains($class, 'VersaModel')) {
                $origin['location'] = 'versaorm_model';
                $origin['type'] = 'orm_model';
                $origin['class'] = $class;
                $origin['function'] = $function;
            } elseif (str_contains($class, 'QueryBuilder')) {
                $origin['location'] = 'versaorm_querybuilder';
                $origin['type'] = 'query_builder';
                $origin['class'] = $class;
                $origin['function'] = $function;
            } elseif (str_contains($class, 'VersaORM')) {
                $origin['location'] = 'versaorm_core';
                $origin['type'] = 'orm_core';
                $origin['class'] = $class;
                $origin['function'] = $function;
            }
        }

        return $origin;
    }

    /**
     * Formatea una query SQL con sus bindings para debugging
     */
    private static function formatQuery(?string $sql, array $bindings = []): ?string
    {
        if (!$sql) {
            return null;
        }

        if (empty($bindings)) {
            return $sql;
        }

        $formatted = $sql;
        foreach ($bindings as $binding) {
            $value = is_string($binding) ? "'{$binding}'" : (string)$binding;
            $formatted = preg_replace('/\?/', $value, $formatted, 1);
        }

        return $formatted;
    }

    /**
     * Genera un stack trace simplificado
     */
    private static function getSimplifiedTrace(array $trace): array
    {
        $simplified = [];
        $maxFrames = 10;
        $count = 0;

        foreach ($trace as $frame) {
            if ($count >= $maxFrames) break;

            $file = $frame['file'] ?? 'unknown';
            $line = $frame['line'] ?? 0;
            $function = $frame['function'] ?? 'unknown';
            $class = $frame['class'] ?? '';

            $simplified[] = [
                'location' => basename($file) . ':' . $line,
                'call' => $class ? "{$class}::{$function}" : $function,
            ];

            $count++;
        }

        return $simplified;
    }

    /**
     * Genera sugerencias basadas en el tipo de error
     */
    private static function generateSuggestions(VersaORMException $exception): array
    {
        $suggestions = [];
        $errorCode = $exception->getErrorCode();
        $message = $exception->getMessage();

        switch ($errorCode) {
            case 'INVALID_IDENTIFIER':
                $suggestions[] = 'Verify that table and column names contain only alphanumeric characters and underscores';
                $suggestions[] = 'Avoid using SQL reserved words as identifiers';
                $suggestions[] = 'Check for potential SQL injection attempts in user input';
                break;

            case 'MASS_ASSIGNMENT_ERROR':
            case 'GUARDED_FIELD_ERROR':
                $suggestions[] = 'Add the field to the $fillable array in your model';
                $suggestions[] = 'Remove the field from the $guarded array if it should be mass assignable';
                $suggestions[] = 'Use individual property assignment instead of mass assignment';
                break;

            case 'VALIDATION_ERROR':
                $suggestions[] = 'Check the validation rules in your model';
                $suggestions[] = 'Ensure all required fields are provided';
                $suggestions[] = 'Verify data types match the expected format';
                break;

            case 'NO_ORM_INSTANCE':
                $suggestions[] = 'Call VersaModel::setORM($ormInstance) before using models';
                $suggestions[] = 'Ensure the ORM instance is properly configured';
                $suggestions[] = 'Check if the database connection is established';
                break;

            case 'PDO_ENGINE_FAILED':
                $suggestions[] = 'Check database connection parameters';
                $suggestions[] = 'Verify the database server is running';
                $suggestions[] = 'Check SQL syntax and table/column names';
                $suggestions[] = 'Review database permissions';
                break;

            case 'FREEZE_VIOLATION':
                $suggestions[] = 'The model is in freeze mode - modifications are not allowed';
                $suggestions[] = 'Call unfreeze() on the model if modifications are needed';
                $suggestions[] = 'Check if freeze mode was enabled intentionally';
                break;

            default:
                if (str_contains($message, 'connection')) {
                    $suggestions[] = 'Check database connection configuration';
                    $suggestions[] = 'Verify database server is accessible';
                    $suggestions[] = 'Check network connectivity';
                }
                if (str_contains($message, 'syntax')) {
                    $suggestions[] = 'Review SQL query syntax';
                    $suggestions[] = 'Check table and column names';
                    $suggestions[] = 'Verify parameter bindings';
                }
                break;
        }

        if (empty($suggestions)) {
            $suggestions[] = 'Check the VersaORM documentation for more information';
            $suggestions[] = 'Enable debug mode for more detailed error information';
        }

        return $suggestions;
    }

    /**
     * Registra el error en el log interno y archivo
     */
    private static function logError(array $errorData): void
    {
        self::$errorLog[] = $errorData;

        // Mantener solo los últimos 100 errores
        if (count(self::$errorLog) > 100) {
            array_shift(self::$errorLog);
        }

        // Escribir a archivo si está configurado el log path
        if (self::$logPath) {
            self::writeErrorToFile($errorData);
        }
    }

    /**
     * Escribe el error a archivo
     */
    private static function writeErrorToFile(array $errorData): void
    {
        if (!self::$logPath) {
            return;
        }

        $logFile = self::$logPath . DIRECTORY_SEPARATOR . 'versaorm_errors_' . date('Y-m-d') . '.log';

        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'error_code' => $errorData['error']['error_code'],
            'message' => $errorData['error']['message'],
            'origin' => $errorData['origin'],
            'query' => $errorData['query']['sql'] ?? null,
            'context' => $errorData['context'],
        ];

        $logLine = json_encode($logEntry, JSON_UNESCAPED_UNICODE) . PHP_EOL;

        // Escribir al archivo de log
        file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
    }

    /**
     * Obtiene el log de errores
     */
    public static function getErrorLog(): array
    {
        return self::$errorLog;
    }

    /**
     * Limpia el log de errores
     */
    public static function clearErrorLog(): void
    {
        self::$errorLog = [];
    }

    /**
     * Formatea un error para mostrar en desarrollo
     */
    public static function formatForDevelopment(array $errorData): string
    {
        $output = "\n" . str_repeat('=', 80) . "\n";
        $output .= "🚨 VersaORM Error Details\n";
        $output .= str_repeat('=', 80) . "\n";

        // Error básico
        $error = $errorData['error'];
        $output .= "Error: {$error['message']}\n";
        $output .= "Code: {$error['error_code']}\n";
        $output .= "Location: {$error['file']}:{$error['line']}\n";

        // Origen
        $origin = $errorData['origin'];
        if ($origin['location'] !== 'unknown') {
            $output .= "Origin: {$origin['type']} in {$origin['location']}\n";
            if ($origin['class']) {
                $output .= "Class: {$origin['class']}::{$origin['function']}\n";
            }
        }

        // Query
        if ($errorData['query']['sql']) {
            $output .= "\nSQL Query:\n";
            $output .= $errorData['query']['formatted_sql'] ?: $errorData['query']['sql'];
            $output .= "\n";
        }

        // Sugerencias
        if (!empty($errorData['suggestions'])) {
            $output .= "\n💡 Suggestions:\n";
            foreach ($errorData['suggestions'] as $suggestion) {
                $output .= "  • {$suggestion}\n";
            }
        }

        // Stack trace simplificado
        if (!empty($errorData['stack_trace'])) {
            $output .= "\n📍 Stack Trace:\n";
            foreach (array_slice($errorData['stack_trace'], 0, 5) as $frame) {
                if (isset($frame['location'])) {
                    $output .= "  {$frame['location']} -> {$frame['call']}\n";
                }
            }
        }

        $output .= str_repeat('=', 80) . "\n";

        return $output;
    }

    /**
     * Formatea un error para producción (información limitada)
     */
    public static function formatForProduction(array $errorData): array
    {
        return [
            'error' => true,
            'message' => 'A database error occurred',
            'code' => $errorData['error']['error_code'],
            'timestamp' => $errorData['context']['timestamp'],
            'reference' => substr(md5(json_encode($errorData)), 0, 8),
        ];
    }

    /**
     * Wrapper para capturar y manejar excepciones automáticamente
     */
    public static function wrap(callable $callback, array $context = [])
    {
        try {
            return $callback();
        } catch (VersaORMException $e) {
            $errorData = self::handleException($e, $context);

            if (self::$debugMode) {
                echo self::formatForDevelopment($errorData);
            }

            throw $e; // Re-lanzar para que el código llamador pueda manejarla
        }
    }
}
