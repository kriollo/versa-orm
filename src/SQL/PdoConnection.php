<?php

declare(strict_types=1);

namespace VersaORM\SQL;

use PDO;
use VersaORM\VersaORMException;

class PdoConnection
{
    private array $config;
    private ?PDO $pdo = null;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function getPdo(): PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }

        $driver = strtolower((string)($this->config['driver'] ?? 'mysql'));
        try {
            switch ($driver) {
                case 'mysql':
                case 'mariadb':
                    $dsn = sprintf(
                        'mysql:host=%s;port=%s;dbname=%s;charset=%s',
                        $this->config['host'] ?? 'localhost',
                        (string)($this->config['port'] ?? '3306'),
                        $this->config['database'] ?? '',
                        $this->config['charset'] ?? 'utf8mb4'
                    );
                    break;
                case 'pgsql':
                case 'postgres':
                case 'postgresql':
                    $dsn = sprintf(
                        'pgsql:host=%s;port=%s;dbname=%s',
                        $this->config['host'] ?? 'localhost',
                        (string)($this->config['port'] ?? '5432'),
                        $this->config['database'] ?? ''
                    );
                    break;
                case 'sqlite':
                    $path = $this->config['database'] ?? ':memory:';
                    $dsn = sprintf('sqlite:%s', $path);
                    break;
                default:
                    throw new VersaORMException('Unsupported PDO driver: ' . $driver);
            }

            $username = (string)($this->config['username'] ?? '');
            $password = (string)($this->config['password'] ?? '');
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ];

            $this->pdo = new PDO($dsn, $username, $password, $options);
        } catch (\Throwable $e) {
            throw new VersaORMException('PDO connection failed: ' . $e->getMessage(), 'PDO_CONNECTION_FAILED');
        }

        return $this->pdo;
    }
}
