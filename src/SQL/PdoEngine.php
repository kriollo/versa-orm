<?php

declare(strict_types=1);

namespace VersaORM\SQL;

use PDO;
use VersaORM\SQL\Dialects\MySQLDialect;
use VersaORM\SQL\Dialects\PostgreSQLDialect;
use VersaORM\SQL\Dialects\SQLiteDialect;
use VersaORM\VersaORMException;

class PdoEngine
{
    private array $config;
    private PdoConnection $connector;
    private SqlDialectInterface $dialect;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->connector = new PdoConnection($config);
        $this->dialect = $this->detectDialect();
        // Provide dialect name hint if supported for SQL generator decisions
        // Ahora todos los dialectos implementan getName()
    }

    private function detectDialect(): SqlDialectInterface
    {
        $driver = strtolower((string)($this->config['driver'] ?? 'mysql'));
        return match ($driver) {
            'mysql', 'mariadb' => new MySQLDialect(),
            'pgsql', 'postgres', 'postgresql' => new PostgreSQLDialect(),
            'sqlite' => new SQLiteDialect(),
            default => new MySQLDialect(),
        };
    }

    public function execute(string $action, array $params)
    {
        $pdo = $this->connector->getPdo();
        // Acción especial 'schema' para introspección mínima (MySQL/SQLite/Postgres)
        if ($action === 'schema') {
            $subject = strtolower((string)($params['subject'] ?? ''));
            if ($subject === 'tables') {
                return $this->fetchTables($pdo);
            }
            if ($subject === 'columns') {
                $table = (string)($params['table_name'] ?? $params['table'] ?? '');
                return $table !== '' ? $this->fetchColumns($pdo, $table) : [];
            }
            return [];
        }

        [$sql, $bindings] = SqlGenerator::generate($action, $params, $this->dialect);

        // Normalización por acción
        if ($action === 'query') {
            $method = (string)($params['method'] ?? 'get');
            // Batch operations mapped to query
            if (in_array($method, ['insertMany', 'updateMany', 'deleteMany', 'upsertMany'], true)) {
                $stmt = $pdo->prepare($sql);
                $stmt->execute($bindings);
                $affected = (int)$stmt->rowCount();
                switch ($method) {
                    case 'insertMany':
                        return [
                            'status' => 'success',
                            'total_inserted' => $affected > 0 ? ($params['records'] ? count($params['records']) : $affected) : 0,
                            'batches_processed' => 1,
                            'batch_size' => (int)($params['batch_size'] ?? count($params['records'] ?? [])),
                        ];
                    case 'updateMany':
                        return [
                            'status' => 'success',
                            'rows_affected' => $affected,
                            'message' => $affected === 0 ? 'No records matched the WHERE conditions' : 'Update completed',
                        ];
                    case 'deleteMany':
                        return [
                            'status' => 'success',
                            'rows_affected' => $affected,
                            'message' => $affected === 0 ? 'No records matched the WHERE conditions' : 'Delete completed',
                        ];
                    case 'upsertMany':
                        return [
                            'status' => 'success',
                            'total_processed' => $params['records'] ? count($params['records']) : $affected,
                            'unique_keys' => $params['unique_keys'] ?? [],
                            'update_columns' => $params['update_columns'] ?? [],
                        ];
                }
            }
            if ($method === 'count') {
                $stmt = $pdo->prepare($sql);
                $stmt->execute($bindings);
                $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
                return (int)($row['count'] ?? 0);
            }
            if ($method === 'exists') {
                $stmt = $pdo->prepare($sql);
                $stmt->execute($bindings);
                $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
                $val = array_values($row)[0] ?? 0;
                return (bool)$val;
            }
            if ($method === 'first') {
                $stmt = $pdo->prepare($sql);
                $stmt->execute($bindings);
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                return $row ?: null;
            }
            // default get
            $stmt = $pdo->prepare($sql);
            $stmt->execute($bindings);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return is_array($rows) ? $rows : [];
        }

        if ($action === 'raw') {
            $stmt = $pdo->prepare($sql);
            $stmt->execute($bindings);
            // intentar devolver filas si hay
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($rows === false) {
                return null;
            }
            return $rows;
        }

        if ($action === 'insert') {
            $stmt = $pdo->prepare($sql);
            $stmt->execute($bindings);
            return (int)$stmt->rowCount();
        }

        if ($action === 'insertGetId') {
            $stmt = $pdo->prepare($sql);
            $stmt->execute($bindings);
            return $pdo->lastInsertId() ?: null;
        }

        if ($action === 'update' || $action === 'delete') {
            $stmt = $pdo->prepare($sql);
            $stmt->execute($bindings);
            return (int)$stmt->rowCount();
        }

        throw new VersaORMException('Unsupported PDO action: ' . $action);
    }

    private function fetchTables(PDO $pdo): array
    {
        $driver = $this->dialect->getName();
        if ($driver === 'mysql') {
            $stmt = $pdo->query('SHOW TABLES');
            $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_NUM) : [];
            $result = [];
            foreach ($rows as $r) {
                $result[] = ['table_name' => $r[0] ?? null];
            }
            return $result;
        }
        if ($driver === 'sqlite') {
            $stmt = $pdo->query("SELECT name as table_name FROM sqlite_master WHERE type='table'");
            return $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
        }
        if ($driver === 'postgres') {
            $stmt = $pdo->query("SELECT tablename AS table_name FROM pg_tables WHERE schemaname='public'");
            return $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
        }
        return [];
    }

    private function fetchColumns(PDO $pdo, string $table): array
    {
        $driver = $this->dialect->getName();
        if ($driver === 'mysql') {
            $stmt = $pdo->prepare('SHOW FULL COLUMNS FROM ' . $this->dialect->quoteIdentifier($table));
            $stmt->execute();
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $result = [];
            foreach ($columns as $col) {
                $type = strtolower((string)($col['Type'] ?? ''));
                $length = null;
                if (preg_match('/^(\w+)\((\d+)\)/', $type, $m) === 1) {
                    $type = $m[1];
                    $length = (int)$m[2];
                }
                $result[] = [
                    'column_name' => $col['Field'] ?? '',
                    'data_type' => $type,
                    'is_nullable' => strtoupper((string)($col['Null'] ?? 'NO')) === 'YES' ? 'YES' : 'NO',
                    'column_default' => $col['Default'] ?? null,
                    'character_maximum_length' => $length,
                    'extra' => $col['Extra'] ?? '',
                ];
            }
            return $result;
        }
        if ($driver === 'sqlite') {
            $stmt = $pdo->prepare('PRAGMA table_info(' . $this->dialect->quoteIdentifier($table) . ')');
            $stmt->execute();
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $result = [];
            foreach ($columns as $col) {
                $result[] = [
                    'column_name' => $col['name'] ?? '',
                    'data_type' => strtolower((string)($col['type'] ?? '')),
                    'is_nullable' => ((int)($col['notnull'] ?? 0)) === 0 ? 'YES' : 'NO',
                    'column_default' => $col['dflt_value'] ?? null,
                    'character_maximum_length' => null,
                    'extra' => ((int)($col['pk'] ?? 0)) === 1 ? 'primary_key' : '',
                ];
            }
            return $result;
        }
        if ($driver === 'postgres') {
            $sql = 'SELECT column_name, data_type, is_nullable, column_default, character_maximum_length ' .
                'FROM information_schema.columns WHERE table_name = ?';
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$table]);
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $result = [];
            foreach ($columns as $col) {
                $result[] = [
                    'column_name' => $col['column_name'] ?? '',
                    'data_type' => strtolower((string)($col['data_type'] ?? '')),
                    'is_nullable' => strtoupper((string)($col['is_nullable'] ?? 'NO')) === 'YES' ? 'YES' : 'NO',
                    'column_default' => $col['column_default'] ?? null,
                    'character_maximum_length' => $col['character_maximum_length'] ?? null,
                    'extra' => '',
                ];
            }
            return $result;
        }
        return [];
    }
}
