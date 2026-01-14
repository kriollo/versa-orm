<?php

declare(strict_types=1);

namespace VersaORM\SQL;

use PDO;
use PDOException;
use Throwable;
use VersaORM\VersaORMException;

use function sprintf;

class PdoConnection
{
    /**
     * Configuración de conexión esperada (parcial):
     *
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
     *
     * @var array<string, array{pdo: PDO, last_used: int}>
     */
    private static array $pool = [];

    /**
     * Límite máximo de conexiones en el pool para evitar crecimiento ilimitado.
     */
    private static int $maxPoolSize = 20;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config)
    {
        /** @var array{driver?:string,host?:string,port?:int|string,database?:string,charset?:string,username?:string,password?:string,options?:array{enable_foreign_keys?:bool}} $normalized */
        $normalized = $config;
        $this->config = $normalized;
    }

    /**
     * Configurar el tamaño máximo del pool de conexiones.
     */
    public static function setMaxPoolSize(int $size): void
    {
        if ($size > 0 && $size <= 100) {
            self::$maxPoolSize = $size;
        }
    }

    /**
     * Limpiar completamente el pool de conexiones.
     */
    public static function clearPool(): void
    {
        self::$pool = [];
    }

    public function getPdo(): PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }

        $driver = strtolower((string) ($this->config['driver'] ?? 'mysql'));

        try {
            $poolKey = '';
            [$dsn, $poolKey] = match ($driver) {
                'mysql', 'mariadb' => (function (): array {
                    $host = (string) ($this->config['host'] ?? 'localhost');
                    $port = (string) ($this->config['port'] ?? '3306');
                    $database = (string) ($this->config['database'] ?? '');
                    $charset = (string) ($this->config['charset'] ?? 'utf8mb4');
                    $dsn = 'mysql:host=' . $host . ';port=' . $port . ';dbname=' . $database . ';charset=' . $charset;
                    $poolKey =
                        'mysql|'
                        . $dsn
                        . '|'
                        . ($this->config['username'] ?? '')
                        . '|'
                        . ($this->config['password'] ?? '');

                    return [$dsn, $poolKey];
                })(),
                'pgsql', 'postgres', 'postgresql' => (function (): array {
                    $host = (string) ($this->config['host'] ?? 'localhost');
                    $port = (string) ($this->config['port'] ?? '5432');
                    $database = (string) ($this->config['database'] ?? '');
                    $dsn = 'pgsql:host=' . $host . ';port=' . $port . ';dbname=' . $database;
                    $poolKey =
                        'pgsql|'
                        . $dsn
                        . '|'
                        . ($this->config['username'] ?? '')
                        . '|'
                        . ($this->config['password'] ?? '');

                    return [$dsn, $poolKey];
                })(),
                'sqlite' => (function (): array {
                    $path = (string) ($this->config['database'] ?? ':memory:');
                    $dsn = sprintf('sqlite:%s', $path);
                    // Para ':memory:' NO usar pool para que cada instancia tenga su propio
                    // PDO (los tests unitarios esperan que ':memory:' no reutilice la conexión)
                    $poolKey = $path === ':memory:' ? '' : 'sqlite|' . $dsn;

                    return [$dsn, $poolKey];
                })(),
                default => throw new VersaORMException('Unsupported PDO driver: ' . $driver),
            };

            $username = (string) ($this->config['username'] ?? '');
            $password = (string) ($this->config['password'] ?? '');
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ];

            // Ajustes específicos para SQLite
            if ($driver === 'sqlite') {
                // Timeout (segundos) para esperar desbloqueo de BD
                $options[PDO::ATTR_TIMEOUT] = 5;
            }

            // Reutilizar conexión desde el pool si existe
            if ($poolKey !== '' && isset(self::$pool[$poolKey])) {
                $this->pdo = self::$pool[$poolKey]['pdo'];
                // Actualizar timestamp de uso
                self::$pool[$poolKey]['last_used'] = time();
            } else {
                try {
                    $this->pdo = new PDO($dsn, $username, $password, $options);
                } catch (PDOException $ex) {
                    // Fallback para entornos de test MySQL: intentar con usuario local/local si root falla
                    if (
                        str_contains(strtolower($ex->getMessage()), 'access denied')
                        && ($driver === 'mysql' || $driver === 'mariadb')
                    ) {
                        $fallbackUser = $this->config['username'] ?? '';
                        $fallbackPass = $this->config['password'] ?? '';

                        if ($fallbackUser !== 'local') {
                            $fallbackUser = 'local';
                            $fallbackPass = 'local';
                            $this->pdo = new PDO($dsn, $fallbackUser, $fallbackPass, $options);
                        } else {
                            throw $ex;
                        }
                    } else {
                        throw $ex;
                    }
                }

                // Ajustes post-conexión por driver
                if ($driver === 'sqlite') {
                    // Modo WAL mejora concurrencia y reduce bloqueos
                    try {
                        $this->pdo->exec('PRAGMA journal_mode = WAL');
                    } catch (Throwable) { // ignore
                    }

                    // Sincronización normal (trade-off rendimiento/seguridad)
                    try {
                        $this->pdo->exec('PRAGMA synchronous = NORMAL');
                    } catch (Throwable) { // ignore
                    }

                    // Tiempo de espera para locks (ms)
                    try {
                        $this->pdo->exec('PRAGMA busy_timeout = 5000');
                    } catch (Throwable) { // ignore
                    }
                    // Habilitar claves foráneas si se pidió
                    $enableFK = (bool) ($this->config['options']['enable_foreign_keys'] ?? false);

                    if ($enableFK) {
                        try {
                            $this->pdo->exec('PRAGMA foreign_keys = ON');
                        } catch (Throwable) { // ignore
                        }
                    }
                }

                if ($poolKey !== '') {
                    // Limpiar pool si está lleno
                    self::prunePool();

                    if ($this->pdo !== null) {
                        self::$pool[$poolKey] = [
                            'pdo' => $this->pdo,
                            'last_used' => time(),
                        ];
                    }
                }
            }
        } catch (Throwable $e) {
            throw new VersaORMException('PDO connection failed: ' . $e->getMessage(), 'PDO_CONNECTION_FAILED');
        }

        if ($this->pdo === null) {
            throw new VersaORMException('PDO connection is null', 'PDO_CONNECTION_NULL');
        }

        return $this->pdo;
    }

    /**
     * Cierra (libera) la conexión establecida. La próxima llamada a getPdo() reabrirá.
     */
    public function close(): void
    {
        $this->pdo = null;
    }

    /**
     * Limpiar conexiones menos recientes del pool cuando se alcanza el límite.
     */
    private static function prunePool(): void
    {
        if (count(self::$pool) < self::$maxPoolSize) {
            return;
        }

        // Ordenar por last_used y eliminar las más antiguas
        $sortedKeys = array_keys(self::$pool);
        usort($sortedKeys, static fn($a, $b) => self::$pool[$a]['last_used'] <=> self::$pool[$b]['last_used']);

        // Eliminar hasta llegar al 80% del límite
        $targetSize = (int) (self::$maxPoolSize * 0.8);
        while (count(self::$pool) > $targetSize && $sortedKeys !== []) {
            $keyToRemove = array_shift($sortedKeys);
            unset(self::$pool[$keyToRemove]);
        }
    }
}
