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
     *   options?:array{enable_foreign_keys?:bool,allow_local_fallback_auth?:bool}
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
        /** @var array{driver?:string,host?:string,port?:int|string,database?:string,charset?:string,username?:string,password?:string,options?:array{enable_foreign_keys?:bool,allow_local_fallback_auth?:bool}} $normalized */
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
    /**
     * Opciones PDO de TLS para MySQL/MariaDB.
     *
     * Claves de configuración admitidas (equivalentes a las de PostgreSQL):
     *  - sslrootcert / ssl_ca   → CA con la que verificar el servidor
     *  - sslcert    / ssl_cert  → certificado de cliente
     *  - sslkey     / ssl_key   → clave privada de cliente
     *  - ssl_cipher             → cifradores permitidos
     *  - sslmode                → 'verify-full'/'verify-ca' exigen verificar el
     *                             certificado del servidor; 'require' cifra sin verificar
     *
     * @return array<int, mixed>
     */
    private function mysqlSslOptions(): array
    {
        $pick = function (string ...$keys): ?string {
            foreach ($keys as $key) {
                $value = $this->config[$key] ?? null;

                if (is_string($value) && $value !== '') {
                    return $value;
                }
            }

            return null;
        };
        $options = [];
        $ca = $pick('sslrootcert', 'ssl_ca');
        $cert = $pick('sslcert', 'ssl_cert');
        $key = $pick('sslkey', 'ssl_key');
        $cipher = $pick('ssl_cipher');

        if ($ca !== null) {
            $options[PDO::MYSQL_ATTR_SSL_CA] = $ca;
        }

        if ($cert !== null) {
            $options[PDO::MYSQL_ATTR_SSL_CERT] = $cert;
        }

        if ($key !== null) {
            $options[PDO::MYSQL_ATTR_SSL_KEY] = $key;
        }

        if ($cipher !== null) {
            $options[PDO::MYSQL_ATTR_SSL_CIPHER] = $cipher;
        }
        $sslmode = strtolower((string) ($this->config['sslmode'] ?? ''));

        // Verificar el certificado del servidor es opt-in explícito: activarlo sin CA
        // configurada rompería conexiones que hoy funcionan.
        if ($options !== [] && defined('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT')) {
            $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = in_array($sslmode, ['verify-ca', 'verify-full'], true);
        }

        return $options;
    }

    /**
     * Clave del pool de conexiones.
     *
     * Las credenciales van hasheadas: antes el password viajaba en claro como *clave de
     * un array estático* de vida larga, así que aparecía en cualquier var_dump, dump de
     * Xdebug o volcado de memoria. El hash distingue igual de bien dos conexiones con el
     * mismo DSN y credenciales distintas.
     */
    private function poolKey(string $driver, string $dsn): string
    {
        return $driver
        . '|'
        . $dsn
        . '|'
        . hash('sha256', ($this->config['username'] ?? '') . "\0" . ($this->config['password'] ?? ''));
    }

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
                    $host = (string) ($this->config['host'] ?? '127.0.0.1');
                    $port = (string) ($this->config['port'] ?? '3306');
                    $database = (string) ($this->config['database'] ?? '');
                    $charset = (string) ($this->config['charset'] ?? 'utf8mb4');
                    $dsn = 'mysql:host=' . $host . ';port=' . $port . ';dbname=' . $database . ';charset=' . $charset;
                    $poolKey = $this->poolKey('mysql', $dsn);

                    return [$dsn, $poolKey];
                })(),
                'pgsql', 'postgres', 'postgresql' => (function (): array {
                    $host = (string) ($this->config['host'] ?? '127.0.0.1');
                    $port = (string) ($this->config['port'] ?? '5432');
                    $database = (string) ($this->config['database'] ?? '');
                    $dsn = 'pgsql:host=' . $host . ';port=' . $port . ';dbname=' . $database;

                    // Soportar opciones de SSL para PostgreSQL
                    // sslmode: disable, allow, prefer, require, verify-ca, verify-full
                    if (isset($this->config['sslmode'])) {
                        $dsn .= ';sslmode=' . (string) $this->config['sslmode'];
                    }

                    // Otras opciones de SSL
                    if (isset($this->config['sslcert'])) {
                        $dsn .= ';sslcert=' . (string) $this->config['sslcert'];
                    }
                    if (isset($this->config['sslkey'])) {
                        $dsn .= ';sslkey=' . (string) $this->config['sslkey'];
                    }
                    if (isset($this->config['sslrootcert'])) {
                        $dsn .= ';sslrootcert=' . (string) $this->config['sslrootcert'];
                    }

                    $poolKey = $this->poolKey('pgsql', $dsn);

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

            // TLS para MySQL/MariaDB. Antes sólo PostgreSQL tenía soporte de SSL, así que
            // no había forma de abrir una conexión MySQL con TLS verificado desde la
            // configuración de la librería: el tráfico iba en claro.
            if ($driver === 'mysql' || $driver === 'mariadb') {
                $options += $this->mysqlSslOptions();
            }

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
                    $allowLocalFallback = (bool) ($this->config['options']['allow_local_fallback_auth'] ?? false);

                    // Fallback opcional para entornos legacy de test MySQL.
                    if (
                        $allowLocalFallback
                        && str_contains(strtolower($ex->getMessage()), 'access denied')
                        && ($driver === 'mysql' || $driver === 'mariadb')
                    ) {
                        $this->pdo = new PDO($dsn, 'local', 'local', $options);
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
