<?php

declare(strict_types=1);

namespace VersaORM;

/**
 * VersaORM - ORM de alto rendimiento para PHP con núcleo en Rust
 * 
 * @package VersaORM
 * @version 1.0.0
 * @author VersaORM Team
 * @license MIT
 */
class VersaORM
{
    // Ruta al binario de Rust. Debería ser configurable.
    private static string $binaryPath = __DIR__ . '/../versaorm_cli/target/release/versaorm_cli';

    // Configuración de la conexión a la base de datos.
    private static array $config = [];

    /**
     * Conecta a la base de datos guardando la configuración.
     *
     * @param array $config
     */
    public static function connect(array $config): void
    {
        self::$config = $config;
    }

    /**
     * Ejecuta un comando en el binario de Rust y devuelve el resultado.
     *
     * @param string $action La acción a realizar (ej. 'query', 'schema').
     * @param array $params Los parámetros para la acción.
     * @return mixed
     * @throws \Exception Si ocurre un error en la ejecución o en la respuesta.
     */
    private static function execute(string $action, array $params)
    {
        if (empty(self::$config)) {
            throw new \Exception('Database configuration is not set. Please call VersaORM::connect() first.');
        }

        $payload = json_encode([
            'config' => self::$config,
            'action' => $action,
            'params' => $params
        ]);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception('Failed to encode JSON payload: ' . json_last_error_msg());
        }

        // Detectar el sistema operativo para usar el binario correcto
        $binaryPath = self::$binaryPath;
        if (PHP_OS_FAMILY === 'Windows') {
            $binaryPath .= '.exe';
        }

        // Verificar que el binario existe
        if (!file_exists($binaryPath)) {
            throw new \Exception("VersaORM binary not found at: {$binaryPath}. Please compile it with: cd versaorm_cli && cargo build --release");
        }

        // Escapamos el JSON para pasarlo como un solo argumento de forma segura
        $command = sprintf('%s %s', $binaryPath, escapeshellarg($payload));

        // Ejecutamos el comando y capturamos la salida
        $output = shell_exec($command);

        if ($output === null) {
            throw new \Exception('Failed to execute the VersaORM binary. Is the path correct and does it have execution permissions?');
        }

        $response = json_decode($output, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception('Failed to decode JSON response from binary: ' . json_last_error_msg());
        }

        if (isset($response['status']) && $response['status'] === 'error') {
            $errorCode = $response['error']['code'] ?? 'UNKNOWN_ERROR';
            $errorMessage = $response['error']['message'] ?? 'An unknown error occurred.';
            throw new \Exception(sprintf('VersaORM Error [%s]: %s', $errorCode, $errorMessage));
        }

        return $response['data'] ?? null;
    }

    /**
     * Inicia un nuevo QueryBuilder para la tabla especificada.
     *
     * @param string $table
     * @return QueryBuilder
     */
    public static function table(string $table): QueryBuilder
    {
        return new QueryBuilder(self::$config, $table);
    }

    /**
     * Ejecuta una consulta SQL personalizada.
     *
     * @param string $query
     * @param array $bindings
     * @return mixed
     */
    public static function exec(string $query, array $bindings = [])
    {
        return self::execute('raw', ['query' => $query, 'bindings' => $bindings]);
    }

    /**
     * Método alias para compatibilidad con código existente.
     *
     * @param string $query
     * @param array $bindings
     * @return mixed
     * @deprecated Usa exec() en su lugar
     */
    public static function raw(string $query, array $bindings = [])
    {
        return self::exec($query, $bindings);
    }

    /**
     * Cierra la conexión a la base de datos.
     *
     * @return void
     */
    public static function disconnect(): void
    {
        self::$config = [];
    }

    /**
     * Obtiene el esquema de la base de datos.
     *
     * @param string $subject
     * @param string|null $tableName
     * @return mixed
     */
    public static function schema(string $subject, ?string $tableName = null)
    {
        $params = ['subject' => $subject];
        if ($tableName !== null) {
            $params['table_name'] = $tableName;
        }
        return self::execute('schema', $params);
    }

    /**
     * Administra el caché interno.
     *
     * @param string $action
     * @return mixed
     */
    public static function cache(string $action)
    {
        return self::execute('cache', ['action' => $action]);
    }

    /**
     * Obtiene la versión actual de VersaORM.
     *
     * @return string
     */
    public static function version(): string
    {
        return '1.0.0';
    }
}
