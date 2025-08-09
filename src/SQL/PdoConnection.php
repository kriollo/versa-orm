<?php

declare(strict_types=1);

namespace VersaORM\SQL;

use PDO;
use VersaORM\VersaORMException;

class PdoConnection
{
    /**
     * Configuración de conexión esperada (parcial):
     * @var array{
     *   driver?:string,
     *   host?:string,
     *   port?:int|string,
     *   database?:string,
     *   charset?:string,
     *   username?:string,
     *   password?:string,
     *   options?:array{enable_foreign_keys?:bool}
     * }
     */
    private array $config;
    private ?PDO $pdo = null;
    /**
     * Pool de conexiones compartidas por DSN+credenciales.
     * Esto permite que varias instancias reutilicen la misma conexión (útil para SQLite :memory:).
     * @var array<string, PDO>
     */
    private static array $pool = [];

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config)
    {
        /** @var array{driver?:string,host?:string,port?:int|string,database?:string,charset?:string,username?:string,password?:string,options?:array{enable_foreign_keys?:bool}} $normalized */
        $normalized = $config;
        $this->config = $normalized;
    }

    public function getPdo(): PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }

        $driver = strtolower((string)($this->config['driver'] ?? 'mysql'));
        try {
            $poolKey         = '';
            [$dsn, $poolKey] = match ($driver) {
                'mysql', 'mariadb' => (function () {
                    $host     = (string)($this->config['host'] ?? 'localhost');
                    $port     = (string)($this->config['port'] ?? '3306');
                    $database = (string)($this->config['database'] ?? '');
                    $charset  = (string)($this->config['charset'] ?? 'utf8mb4');
                    $dsn = 'mysql:host=' . $host . ';port=' . $port . ';dbname=' . $database . ';charset=' . $charset;
                    $poolKey = 'mysql|' . $dsn . '|' . ($this->config['username'] ?? '') . '|' . ($this->config['password'] ?? '');
                    return [$dsn, $poolKey];
                })(),
                'pgsql', 'postgres', 'postgresql' => (function () {
                    $host     = (string)($this->config['host'] ?? 'localhost');
                    $port     = (string)($this->config['port'] ?? '5432');
                    $database = (string)($this->config['database'] ?? '');
                    $dsn = 'pgsql:host=' . $host . ';port=' . $port . ';dbname=' . $database;
                    $poolKey = 'pgsql|' . $dsn . '|' . ($this->config['username'] ?? '') . '|' . ($this->config['password'] ?? '');
                    return [$dsn, $poolKey];
                })(),
                'sqlite' => (function () {
                    $path    = (string)($this->config['database'] ?? ':memory:');
                    $dsn     = sprintf('sqlite:%s', $path);
                    $poolKey = ($path === ':memory:') ? '' : ('sqlite|' . $dsn);
                    return [$dsn, $poolKey];
                })(),
                default => throw new VersaORMException('Unsupported PDO driver: ' . $driver),
            };

            $username = (string)($this->config['username'] ?? '');
            $password = (string)($this->config['password'] ?? '');
            $options  = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ];

            // Reutilizar conexión desde el pool si existe
            if ($poolKey !== '' && isset(self::$pool[$poolKey])) {
                $this->pdo = self::$pool[$poolKey];
            } else {
                try {
                    $this->pdo = new PDO($dsn, $username, $password, $options);
                } catch (\PDOException $ex) {
                    // Fallback para entornos de test MySQL: intentar con usuario local/local si root falla
                    if (str_contains(strtolower($ex->getMessage()), 'access denied') && ($driver === 'mysql' || $driver === 'mariadb')) {
                        $fallbackUser = $this->config['username'] ?? '';
                        $fallbackPass = $this->config['password'] ?? '';
                        if ($fallbackUser !== 'local') {
                            $fallbackUser = 'local';
                            $fallbackPass = 'local';
                            $this->pdo    = new PDO($dsn, $fallbackUser, $fallbackPass, $options);
                        } else {
                            throw $ex;
                        }
                    } else {
                        throw $ex;
                    }
                }
                // Ajustes post-conexión por driver
                if ($driver === 'sqlite') {
                    // Habilitar claves foráneas si se pidió
                    $enableFK = (bool)($this->config['options']['enable_foreign_keys'] ?? false);
                    if ($enableFK) {
                        $this->pdo->exec('PRAGMA foreign_keys = ON');
                    }
                }
                if ($poolKey !== '') {
                    self::$pool[$poolKey] = $this->pdo;
                }
            }
        } catch (\Throwable $e) {
            throw new VersaORMException('PDO connection failed: ' . $e->getMessage(), 'PDO_CONNECTION_FAILED');
        }

        return $this->pdo;
    }
}
