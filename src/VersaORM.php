<?php

declare(strict_types=1);

namespace VersaORM;

/**
 * VersaORM - ORM de alto rendimiento para PHP con núcleo en Rust
 *
 * PROPÓSITO: Configuración general del ORM y acceso al motor SQL
 * FUNCIONALIDAD:
 * - Gestión de configuración de conexión
 * - Ejecución de consultas SQL directas (exec, raw)
 * - Factory para QueryBuilder (table)
 * - Administración de esquema y caché
 * - Conexión con binario Rust
 *
 * NOTA: Todos los métodos de consulta y manipulación de datos
 * están ahora en VersaModel para una arquitectura más limpia.
 *
 * @package VersaORM
 * @version 1.0.0
 * @author VersaORM Team
 * @license MIT
 */
class VersaORM
{
    // Ruta al binario de Rust. Se detecta automáticamente según el OS.
    private string $binaryPath;

    /** @var array<string, mixed> */
    private array $config = [];

    /**
     * Constructor de la clase VersaORM.
     *
     * @param array<string, mixed> $config Configuración de la base de datos
     */
    public function __construct(array $config = [])
    {
        $this->setBinaryPath();
        $this->checkRustBinary();

        if (!empty($config)) {
            $this->config = $config;
        }
    }

    /**
     * Configura la conexión de la instancia.
     *
     * @param array<string, mixed> $config
     * @return void
     */
    public function setConfig(array $config): void
    {
        $this->config = $config;
    }

    /**
     * Obtiene la configuración actual.
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Ejecuta un comando usando la configuración de instancia.
     *
     * @param string $action
     * @param array<string, mixed> $params
     * @return mixed
     * @throws VersaORMException
     */
    private function execute(string $action, array $params)
    {
        if (empty($this->config)) {
            throw new VersaORMException('Database configuration is not set. Please call setConfig() first.');
        }

        // Validar parámetros de entrada
        $this->validateInput($action, $params);


        try {
            $payload = json_encode([
                'config' => $this->config,
                'action' => $action,
                'params' => $params
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);

            // If in debug mode and JSON_DUMP environment variable is set, dump and exit
            if ($this->isDebugMode() && getenv('JSON_DUMP') === 'true') {
                echo "=== JSON PAYLOAD DUMP ===\n";
                echo $payload . "\n";
                echo "========================\n";
                exit(0);
            }
        } catch (\JsonException $e) {
            throw new VersaORMException(sprintf(
                'Failed to encode JSON payload: %s. Data contains invalid characters or circular references.',
                $e->getMessage()
            ), 'JSON_ENCODE_ERROR');
        }

        $binaryPath = $this->binaryPath;

        if (!file_exists($binaryPath)) {
            throw new VersaORMException(sprintf(
                'VersaORM binary not found at: %s. Please ensure the binary is compiled and accessible.',
                $binaryPath
            ), 'BINARY_NOT_FOUND');
        }

        // Verificar permisos de ejecución
        if (!is_executable($binaryPath)) {
            throw new VersaORMException(sprintf(
                'VersaORM binary is not executable: %s. Please check file permissions.',
                $binaryPath
            ), 'BINARY_NOT_EXECUTABLE');
        }

        // Usar método más seguro con archivo temporal para evitar problemas de escape
        $output = $this->executeBinaryWithTempFile($binaryPath, $payload);

        if ($output === null) {
            throw new VersaORMException(
                'Failed to execute the VersaORM binary. This could be due to:\n' .
                    '- Binary corruption\n' .
                    '- System resource limitations\n' .
                    '- Security restrictions\n' .
                    '- Missing system dependencies',
                'BINARY_EXECUTION_FAILED'
            );
        }

        // Intentar decodificar la respuesta JSON
        try {
            $response = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new VersaORMException(
                sprintf(
                    'Failed to decode JSON response from binary: %s\nRaw output: %s',
                    $e->getMessage(),
                    substr($output, 0, 500) // Limitar la salida para evitar spam
                ),
                'JSON_DECODE_ERROR'
            );
        }

        // Manejar errores del binario
        if (is_array($response) && isset($response['status']) && $response['status'] === 'error') {
            $this->handleBinaryError($response, $action, $params);
        }

        return is_array($response) ? ($response['data'] ?? null) : null;
    }


    /**
     * Crea un QueryBuilder para la tabla especificada.
     *
     * @param string $table
     * @return QueryBuilder
     */
    public function table(string $table): QueryBuilder
    {
        return new QueryBuilder($this, $table);
    }



    /**
     * Ejecuta una consulta SQL personalizada.
     *
     * @param string $query
     * @param array<int, mixed> $bindings
     * @return mixed
     */
    public function exec(string $query, array $bindings = [])
    {
        return $this->execute('raw', ['query' => $query, 'bindings' => $bindings]);
    }

    /**
     * Método alias para compatibilidad con código existente.
     *
     * @param string $query
     * @param array<int, mixed> $bindings
     * @return mixed
     * @deprecated Usa exec() en su lugar
     */
    public function raw(string $query, array $bindings = [])
    {
        return $this->exec($query, $bindings);
    }

    /**
     * Obtiene el esquema de la base de datos.
     *
     * @param string $subject
     * @param string|null $tableName
     * @return mixed
     */
    public function schema(string $subject, ?string $tableName = null)
    {
        $params = ['subject' => $subject];
        if ($tableName !== null) {
            $params['table_name'] = $tableName;
        }
        return $this->execute('schema', $params);
    }

    /**
     * Administra el caché interno.
     *
     * @param string $action
     * @return mixed
     */
    public function cache(string $action)
    {
        return $this->execute('cache', ['action' => $action]);
    }

    /**
     * Obtiene la versión actual de VersaORM.
     *
     * @return string
     */
    public function version(): string
    {
        return '1.0.0';
    }

    /**
     * Cierra la conexión a la base de datos (limpia la configuración).
     *
     * @return bool
     */
    public function disconnect(): bool
    {
        $this->config = [];
        return true;
    }

    /**
     * Valida los parámetros de entrada antes de ejecutar comandos.
     *
     * @param string $action
     * @param array<string, mixed> $params
     * @return void
     * @throws VersaORMException
     */
    private function validateInput(string $action, array $params): void
    {
        // Validar que la acción no esté vacía
        if (empty($action)) {
            throw new VersaORMException('Action parameter cannot be empty.');
        }

        // Validar acciones conocidas
        $validActions = ['query', 'raw', 'schema', 'cache'];
        if (!in_array($action, $validActions)) {
            throw new VersaORMException(sprintf(
                'Invalid action: %s. Valid actions are: %s',
                $action,
                implode(', ', $validActions)
            ));
        }

        // Validaciones específicas por acción
        switch ($action) {
            case 'raw':
                if (!isset($params['query']) || !is_string($params['query'])) {
                    throw new VersaORMException('Raw action requires a valid query string.', 'INVALID_QUERY');
                }
                if (strlen($params['query']) > 1000000) { // 1MB limit
                    throw new VersaORMException('Query string exceeds maximum length (1MB).', 'QUERY_TOO_LONG');
                }
                break;

            case 'schema':
                if (!isset($params['subject']) || !is_string($params['subject'])) {
                    throw new VersaORMException('Schema action requires a valid subject.', 'INVALID_SCHEMA_SUBJECT');
                }
                break;

            case 'cache':
                if (!isset($params['action']) || !is_string($params['action'])) {
                    throw new VersaORMException('Cache action requires a valid action parameter.', 'INVALID_CACHE_ACTION');
                }
                break;
        }

        // Validar que los parámetros no contengan referencias circulares
        $this->checkCircularReferences($params);
    }


    /**
     * Maneja errores devueltos por el binario de Rust.
     *
     * @param array<string, mixed> $response
     * @param string $action
     * @param array<string, mixed> $params
     * @return void
     * @throws VersaORMException
     */
    private function handleBinaryError(array $response, string $action, array $params): void
    {
        $error = $response['error'] ?? [];
        $errorCode = is_array($error) && isset($error['code']) && is_string($error['code']) ? $error['code'] : 'UNKNOWN_ERROR';
        $errorMessage = is_array($error) && isset($error['message']) && is_string($error['message']) ? $error['message'] : 'An unknown error occurred.';
        $errorDetails = is_array($error) && isset($error['details']) && is_array($error['details']) ? $error['details'] : [];
        $sqlState = is_array($error) && isset($error['sql_state']) && is_string($error['sql_state']) ? $error['sql_state'] : null;

        // Extraer información de la consulta desde el error de Rust (si está disponible)
        $sqlQuery = is_array($error) && isset($error['query']) && is_string($error['query']) ? $error['query'] : null;
        $sqlBindings = is_array($error) && isset($error['bindings']) && is_array($error['bindings']) ? $error['bindings'] : [];

        // Crear información de consulta para el mensaje de error
        $query = null;
        $bindings = [];

        if ($sqlQuery) {
            // Si tenemos la query SQL real desde Rust, usarla
            $query = $sqlQuery;
            $bindings = $sqlBindings;
        } elseif ($action === 'raw') {
            // Para consultas raw, usar los parámetros originales
            $query = isset($params['query']) && is_string($params['query']) ? $params['query'] : null;
            $bindings = isset($params['bindings']) && is_array($params['bindings']) ? $params['bindings'] : [];
        } elseif ($action === 'query') {
            // Para QueryBuilder, construir una representación de la consulta como fallback
            $table = isset($params['table']) && is_string($params['table']) ? $params['table'] : 'unknown';
            $method = isset($params['method']) && is_string($params['method']) ? $params['method'] : 'get';
            $select = isset($params['select']) && is_array($params['select']) ? $params['select'] : ['*'];
            $where = isset($params['where']) && is_array($params['where']) ? $params['where'] : [];
            $orderBy = isset($params['orderBy']) && is_array($params['orderBy']) ? $params['orderBy'] : [];
            $limit = isset($params['limit']) && (is_int($params['limit']) || is_string($params['limit'])) ? $params['limit'] : null;

            $query = "QueryBuilder: table={$table}, method={$method}, select=" . implode(',', $select);
            if (!empty($where)) {
                $whereDesc = [];
                foreach ($where as $w) {
                    if (is_array($w) && (($w['operator'] ?? null) === 'RAW') && isset($w['value']) && is_array($w['value'])) {
                        // Manejo especial para whereRaw
                        $rawSql = isset($w['value']['sql']) && is_string($w['value']['sql']) ? $w['value']['sql'] : 'unknown';
                        $rawBindings = isset($w['value']['bindings']) && is_array($w['value']['bindings']) ? $w['value']['bindings'] : [];
                        $bindingsStr = !empty($rawBindings) ? ' [bindings: ' . json_encode($rawBindings) . ']' : '';
                        $whereDesc[] = "RAW({$rawSql}){$bindingsStr}";
                    } elseif (is_array($w) && isset($w['value']) && is_array($w['value'])) {
                        $value = '[' . implode(',', $w['value']) . ']';
                        $whereDesc[] = "{$w['column']} {$w['operator']} {$value}";
                    } elseif (is_array($w)) {
                        $value = (string)($w['value'] ?? '');
                        $whereDesc[] = "{$w['column']} {$w['operator']} {$value}";
                    }
                }
                $query .= ", where=[" . implode(' AND ', $whereDesc) . "]";
            }
            if (!empty($orderBy) && isset($orderBy[0]) && is_array($orderBy[0])) {
                $query .= ", orderBy={$orderBy[0]['column']} {$orderBy[0]['direction']}";
            }
            if ($limit) {
                $query .= ", limit=" . strval($limit);
            }
        }

        // Verificar si está en modo debug
        $isDebugMode = $this->isDebugMode();

        // Construir mensaje de error según el modo
        if ($isDebugMode) {
            $detailedMessage = $this->buildDetailedErrorMessage(
                $errorCode,
                $errorMessage,
                $errorDetails,
                $sqlState,
                $action,
                $query,
                $bindings
            );

            // En modo debug, agregar stack trace
            $detailedMessage .= "\n\n=== DEBUG STACK TRACE ===\n";
            $detailedMessage .= $this->getDebugStackTrace();

            // Log del error si está habilitado
            $this->logError($errorCode, $errorMessage, $query, $bindings, $detailedMessage);
        } else {
            // Mensaje resumido para producción
            $detailedMessage = $this->buildSimpleErrorMessage($errorCode, $errorMessage);
        }

        throw new VersaORMException(
            $detailedMessage,
            $errorCode,
            $query,
            $bindings,
            $errorDetails,
            $sqlState
        );
    }

    /**
     * Construye un mensaje de error detallado.
     *
     * @param string $errorCode
     * @param string $errorMessage
     * @param array<string, mixed> $errorDetails
     * @param string|null $sqlState
     * @param string $action
     * @param string|null $query
     * @param array<int, mixed> $bindings
     * @return string
     */
    private function buildDetailedErrorMessage(
        string $errorCode,
        string $errorMessage,
        array $errorDetails,
        ?string $sqlState,
        string $action,
        ?string $query,
        array $bindings = []
    ): string {
        $message = sprintf('VersaORM Error [%s]: %s', $errorCode, $errorMessage);

        // Añadir la consulta y parámetros al mensaje de error si están disponibles
        if ($query !== null) {
            $message .= sprintf('\n\nQuery: %s', $query);
        }
        if (!empty($bindings)) {
            $message .= sprintf('\n\nBindings: %s', json_encode($bindings));
        }

        if ($sqlState) {
            $message .= sprintf('\nSQL State: %s', $sqlState);
        }

        // Agregar sugerencias basadas en el tipo de error
        $suggestions = $this->getErrorSuggestions($errorCode, $errorMessage);
        if (!empty($suggestions)) {
            $message .= '\n\nSuggestions:';
            foreach ($suggestions as $suggestion) {
                $message .= '\n- ' . $suggestion;
            }
        }

        // Agregar detalles adicionales si están disponibles
        if (!empty($errorDetails)) {
            $message .= '\n\nDetails:';
            foreach ($errorDetails as $key => $value) {
                $message .= sprintf('\n- %s: %s', $key, is_scalar($value) ? (string)$value : json_encode($value));
            }
        }

        // Agregar información de contexto
        $message .= sprintf('\n\nContext: Action=%s', $action);
        if ($query !== null) {
            if (strlen($query) < 200) {
                $message .= sprintf(', Query=%s', $query);
            } else {
                $message .= sprintf(', Query=%s...', substr($query, 0, 200));
            }
        }

        return $message;
    }

    /**
     * Construye un mensaje de error simple para modo producción.
     *
     * @param string $errorCode
     * @param string $errorMessage
     * @return string
     */
    private function buildSimpleErrorMessage(string $errorCode, string $errorMessage): string
    {
        return sprintf('Database Error [%s]: %s', $errorCode, $errorMessage);
    }

    /**
     * Verifica si está habilitado el modo debug.
     *
     * @return bool
     */
    private function isDebugMode(): bool
    {
        return isset($this->config['debug']) && $this->config['debug'] === true;
    }

    /**
     * Obtiene el stack trace para modo debug.
     *
     * @return string
     */
    private function getDebugStackTrace(): string
    {
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
        $traceStr = '';

        foreach ($trace as $i => $frame) {
            if (isset($frame['file']) && isset($frame['line'])) {
                $file = basename($frame['file']);
                $line = $frame['line'];
                $function = $frame['function'];
                $class = isset($frame['class']) ? $frame['class'] . '::' : '';

                $traceStr .= sprintf("#%d %s%s() at %s:%d\n", $i, $class, $function, $file, $line);
            }
        }

        return $traceStr;
    }

    /**
     * Registra el error en log si está en modo debug.
     *
     * @param string $errorCode
     * @param string $errorMessage
     * @param string|null $query
     * @param array<int, mixed> $bindings
     * @param string $fullMessage
     * @return void
     */
    private function logError(string $errorCode, string $errorMessage, ?string $query, array $bindings, string $fullMessage): void
    {
        if (!$this->isDebugMode()) {
            return;
        }

        try {
            $logDir = __DIR__ . '/../logs';
            if (!is_dir($logDir)) {
                if (!mkdir($logDir, 0755, true) && !is_dir($logDir)) {
                    throw new \RuntimeException(sprintf('Directory "%s" was not created', $logDir));
                }
            }

            // Usar archivo con fecha actual (YYYY-MM-DD.log)
            $logFile = $logDir . '/' . date('Y-m-d') . '.log';
            $timestamp = date('Y-m-d H:i:s');

            $logEntry = sprintf(
                "[%s] [PHP] [ERROR] [%s] %s\n" .
                    "[%s] [PHP] [QUERY] %s\n" .
                    "[%s] [PHP] [BINDINGS] %s\n" .
                    "[%s] [PHP] [FULL_ERROR] %s\n\n",
                $timestamp,
                $errorCode,
                $errorMessage,
                $timestamp,
                $query ?? 'N/A',
                $timestamp,
                json_encode($bindings),
                $timestamp,
                str_replace("\n", " | ", $fullMessage)
            );

            file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);

            // Limpiar logs antiguos (mantener solo 7 días)
            $this->cleanOldLogs($logDir);
        } catch (\Throwable $e) {
            // Silenciar errores de logging para no interferir con el error principal
        }
    }

    /**
     * Limpia archivos de log antiguos (más de 7 días).
     *
     * @param string $logDir
     * @return void
     */
    private function cleanOldLogs(string $logDir): void
    {
        try {
            $files = glob($logDir . '/*.log');
            if ($files === false) {
                return;
            }
            $sevenDaysAgo = strtotime('-7 days');

            foreach ($files as $file) {
                $filename = basename($file, '.log');

                // Si es un archivo con formato de fecha YYYY-MM-DD
                if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $filename)) {
                    $fileDate = strtotime($filename);
                    if ($fileDate !== false && $sevenDaysAgo !== false && $fileDate < $sevenDaysAgo) {
                        unlink($file);
                    }
                }
            }
        } catch (\Throwable $e) {
            // Silenciar errores de limpieza de logs
        }
    }

    /**
     * Proporciona sugerencias basadas en el tipo de error.
     *
     * @param string $errorCode
     * @param string $errorMessage
     * @return array<int, string>
     */
    private function getErrorSuggestions(string $errorCode, string $errorMessage): array
    {
        $suggestions = [];
        $lowerMessage = strtolower($errorMessage);

        // Errores de conexión
        if (str_contains($lowerMessage, 'connection') || str_contains($lowerMessage, 'connect')) {
            $suggestions[] = 'Check database server is running';
            $suggestions[] = 'Verify connection parameters (host, port, credentials)';
            $suggestions[] = 'Check network connectivity';
            $suggestions[] = 'Verify firewall settings';
        }

        // Errores de tabla no encontrada
        if (str_contains($lowerMessage, 'table') && str_contains($lowerMessage, 'not found')) {
            $suggestions[] = 'Check if the table name is spelled correctly';
            $suggestions[] = 'Verify the table exists in the database';
            $suggestions[] = 'Check if you have permissions to access the table';
            $suggestions[] = 'Ensure you are connected to the correct database';
        }

        // Errores de columna no encontrada
        if (str_contains($lowerMessage, 'column') && str_contains($lowerMessage, 'not found')) {
            $suggestions[] = 'Check if the column name is spelled correctly';
            $suggestions[] = 'Verify the column exists in the table';
            $suggestions[] = 'Check the table schema';
        }

        // Errores de sintaxis SQL
        if (str_contains($lowerMessage, 'syntax')) {
            $suggestions[] = 'Check SQL syntax for typos';
            $suggestions[] = 'Verify proper use of quotes and parentheses';
            $suggestions[] = 'Check if keywords are properly escaped';
        }

        // Errores de restricción/integridad
        if (str_contains($lowerMessage, 'constraint') || str_contains($lowerMessage, 'duplicate')) {
            $suggestions[] = 'Check for duplicate values in unique fields';
            $suggestions[] = 'Verify foreign key references are valid';
            $suggestions[] = 'Check required fields are not null';
        }

        // Errores de permisos
        if (str_contains($lowerMessage, 'permission') || str_contains($lowerMessage, 'access denied')) {
            $suggestions[] = 'Check database user permissions';
            $suggestions[] = 'Verify user has required privileges for the operation';
            $suggestions[] = 'Contact database administrator';
        }

        // Errores de tipo de datos
        if (str_contains($lowerMessage, 'type') || str_contains($lowerMessage, 'invalid')) {
            $suggestions[] = 'Check data types match column definitions';
            $suggestions[] = 'Verify date/time formats are correct';
            $suggestions[] = 'Check numeric values are within valid ranges';
        }

        return $suggestions;
    }

    /**
     * Verifica referencias circulares en los parámetros.
     *
     * @param mixed $data
     * @param array<int, string> $visited
     * @return void
     * @throws VersaORMException
     */
    private function checkCircularReferences($data, array &$visited = []): void
    {
        // Solo verificar objetos reales, no arrays convertidos
        if (is_object($data)) {
            $hash = spl_object_hash($data);
            if (in_array($hash, $visited)) {
                throw new VersaORMException('Circular reference detected in parameters.');
            }
            $visited[] = $hash;

            if (method_exists($data, 'toArray')) {
                $this->checkCircularReferences($data->toArray(), $visited);
            } elseif ($data instanceof \Traversable) {
                foreach ($data as $value) {
                    $this->checkCircularReferences($value, $visited);
                }
            }

            array_pop($visited);
        } elseif (is_array($data)) {
            // Para arrays, solo verificar si tienen referencias reales de objetos
            foreach ($data as $value) {
                if (is_object($value) || (is_array($value) && !empty($value))) {
                    $this->checkCircularReferences($value, $visited);
                }
            }
        }
    }

    /**
     * Ejecuta el binario usando un archivo temporal para evitar problemas de escape.
     *
     * @param string $binaryPath
     * @param string $payload
     * @return string|null
     */
    private function executeBinaryWithTempFile(string $binaryPath, string $payload): ?string
    {
        // Crear archivo temporal seguro
        $tempFile = tempnam(sys_get_temp_dir(), 'versaorm_');
        if ($tempFile === false) {
            throw new VersaORMException('Failed to create temporary file for binary execution.', 'TEMP_FILE_ERROR');
        }

        try {
            // Escribir payload al archivo temporal
            if (file_put_contents($tempFile, $payload, LOCK_EX) === false) {
                throw new VersaORMException('Failed to write to temporary file.', 'TEMP_FILE_WRITE_ERROR');
            }

            // Construir comando usando el archivo temporal
            $command = sprintf('%s %s 2>&1', escapeshellarg($binaryPath), escapeshellarg("@$tempFile"));

            // Ejecutar comando
            $output = shell_exec($command);

            return $output !== false ? $output : null;
        } finally {
            // Limpiar archivo temporal independientemente del resultado
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }


    /**
     * Establece la ruta del binario según el sistema operativo.
     *
     * @return void
     */
    private function setBinaryPath(): void
    {
        $binaryDir = __DIR__ . '/binary';

        switch (PHP_OS_FAMILY) {
            case 'Windows':
                $this->binaryPath = $binaryDir . '/versaorm_cli.exe';
                break;
            case 'Linux':
                $this->binaryPath = $binaryDir . '/versaorm_cli_linux';
                break;
            case 'Darwin': // macOS
                $this->binaryPath = $binaryDir . '/versaorm_cli_darwin';
                break;
            default:
                // Fallback para sistemas desconocidos
                $this->binaryPath = $binaryDir . '/versaorm_cli_linux';
                break;
        }
    }

    /**
     * Verifica la existencia del binario de Rust.
     *
     * @return void
     * @throws \RuntimeException
     */
    private function checkRustBinary(): void
    {
        if (!file_exists($this->binaryPath)) {
            $osName = strtolower(PHP_OS_FAMILY);
            $expectedName = "versaorm_cli_{\$osName}" . (PHP_OS_FAMILY === 'Windows' ? '.exe' : '');

            throw new \RuntimeException(
                "VersaORM binary not found at: {
                $this->binaryPath}
\n\n" .
                    "Expected binary name: {
                    $expectedName}
\n\n" .
                    "To fix this:\n" .
                    "1. Compile the binary: cd versaorm_cli && cargo build --release\n" .
                    "2. Copy to: src/binary/{
                    $expectedName}\n\n" .
                    "For cross-compilation, see src/binary/README.md"
            );
        }

        // En sistemas Unix, verificar permisos de ejecución
        if (PHP_OS_FAMILY !== 'Windows' && !is_executable($this->binaryPath)) {
            throw new \RuntimeException(
                "VersaORM binary exists but is not executable: {
                $this->binaryPath}
\n\n" .
                    "Fix with: chmod +x {
                    $this->binaryPath}"
            );
        }
    }
}
