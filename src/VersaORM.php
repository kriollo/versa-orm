<?php

declare(strict_types=1);

namespace VersaORM;

use Exception;
use InvalidArgumentException;
use JsonException;
use RuntimeException;
use Throwable;
use Traversable;
use VersaORM\SQL\PdoEngine;

use function in_array;
use function is_array;
use function is_bool;
use function is_int;
use function is_object;
use function is_resource;
use function is_scalar;
use function is_string;
use function sprintf;
use function strlen;

/**
 * Definiciones de tipos Psalm para estructuras internas de esquema y operaciones.
 * Se usan para eliminar usages "mixed" y dar forma explícita a arrays asociativos.
 *
 * @psalm-type ColumnDef = array{
 *   name?:string,
 *   type?:string,
 *   nullable?:bool,
 *   default?:mixed,
 *   primary?:bool,
 *   autoIncrement?:bool
 * }
 * @psalm-type UniqueConstraintDef = array{
 *   name?:string,
 *   columns?:list<string>
 * }
 * @psalm-type ForeignConstraintDef = array{
 *   name?:string,
 *   columns?:list<string>,
 *   refTable?:string,
 *   refColumns?:list<string>,
 *   onDelete?:string,
 *   onUpdate?:string
 * }
 * @psalm-type TableConstraintsDef = array{
 *   unique?:list<UniqueConstraintDef>,
 *   foreign?:list<ForeignConstraintDef>
 * }
 * @psalm-type IndexColumn = string|array{raw?:string}
 * @psalm-type IndexDef = array{
 *   name?:string,
 *   columns?:list<IndexColumn>,
 *   unique?:bool,
 *   using?:string,
 *   where?:string,
 *   if_not_exists?:bool,
 *   concurrently?:bool
 * }
 * @psalm-type AlterRenameDef = array{from?:string,to?:string}
 * @psalm-type AlterModifyDef = array{name?:string,type?:string,nullable?:bool,default?:mixed}
 * @psalm-type AlterChanges = array{
 *   add?:list<ColumnDef>,
 *   addIndex?:list<IndexDef>,
 *   dropIndex?:list<string>,
 *   addForeign?:list<ForeignConstraintDef>,
 *   dropForeign?:list<string>,
 *   rename?:list<AlterRenameDef>,
 *   drop?:list<string>,
 *   modify?:list<AlterModifyDef>
 * }
 */
/**
 * VersaORM - ORM de alto rendimiento para PHP con núcleo en Rust.
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
 * @version 1.0.0
 *
 * @author  VersaORM Team
 * @license MIT
 */
class VersaORM
{
    // Ruta al binario de Rust. Se detecta automáticamente según el OS.
    private string $binaryPath;

    /**
     * Configuración principal del ORM (forma parcial esperada).
     *
     * @var array{
     *   engine?:string,
     *   driver?:string,
     *   host?:string,
     *   port?:int|string,
     *   database?:string,
     *   database_type?:string,
     *   charset?:string,
     *   username?:string,
     *   password?:string,
     *   debug?:bool,
     *   options?:array<string,mixed>
     * }
     */
    private array $config = [];

    /**
     * @var bool Estado global del modo freeze
     */
    private bool $isFrozen = false;

    /**
     * Estados freeze por modelo (class-string => bool).
     *
     * @var array<string,bool>
     */
    private array $frozenModels = [];

    /**
     * Instancia persistente del motor PDO para esta instancia de ORM.
     * Permite reutilizar la misma conexión (crítico para SQLite :memory:).
     */
    private ?PdoEngine $pdoEngine = null;

    /**
     * Constructor de la clase VersaORM.
     *
     * @param array<string, mixed> $config Configuración de la base de datos
     */
    /**
     * @param array<string,mixed> $config
     */
    public function __construct(array $config = [])
    {
        // Establecer configuración primero para decidir motor. Por defecto: PDO.
        if ($config !== []) {
            /** @var array{engine?:string,driver?:string,host?:string,port?:int|string,database?:string,database_type?:string,charset?:string,username?:string,password?:string,debug?:bool,options?:array<string,mixed>} $normalized */
            $normalized = $config;
            $this->config = $normalized;
        }

        // Configurar ErrorHandler con la configuración de VersaORM
        ErrorHandler::configureFromVersaORM($this->config);

        // Forzar engine por defecto a 'pdo' si no se indica explícitamente 'rust'
        $engine = strtolower((string) ($this->config['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

        if ($engine === '' || $engine === 'default') {
            $engine = 'pdo';
            $this->config['engine'] = 'pdo';
        }

        // Inicializar binario solo si se solicita backend rust explícitamente
        if ($engine === 'rust') {
            $this->setBinaryPath();
            $this->checkRustBinary();
        }
    }

    /**
     * Configura la conexión de la instancia.
     *
     * @param array<string, mixed> $config
     */
    /** @param array<string,mixed> $config */
    public function setConfig(array $config): void
    {
        /** @var array{engine?:string,driver?:string,host?:string,port?:int|string,database?:string,database_type?:string,charset?:string,username?:string,password?:string,debug?:bool,options?:array<string,mixed>} $normalized */
        $normalized = $config;
        $this->config = $normalized;
    }

    /**
     * Obtiene la configuración actual.
     *
     * @return array<string, mixed>
     */
    /** @return array<string,mixed> */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Devuelve métricas internas del motor PDO (si está en uso).
     *
     * @return array<string,float|int>|null
     */
    public function metrics(): ?array
    {
        $engine = strtolower((string) ($this->config['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

        if ($engine !== 'pdo') {
            return null; // Métricas actuales sólo para motor PDO
        }

        if (! $this->pdoEngine instanceof PdoEngine) {
            // Forzar inicialización perezosa para disponer de métricas
            $this->pdoEngine = new PdoEngine($this->config, function (string $message, array $context = []): void {
                $this->logDebug($message, $context);
            });
        }

        return PdoEngine::getMetrics();
    }

    /**
     * Reinicia métricas y cache de sentencias preparadas del motor PDO.
     */
    public function metricsReset(): void
    {
        $engine = strtolower((string) ($this->config['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

        if ($engine !== 'pdo') {
            return;
        }

        if (! $this->pdoEngine instanceof PdoEngine) {
            $this->pdoEngine = new PdoEngine($this->config, function (string $message, array $context = []): void {
                $this->logDebug($message, $context);
            });
        }
        $this->pdoEngine->resetAllMetrics();
    }

    /**
     * Desconecta explícitamente la conexión subyacente (usado en servidores persistentes/CLI largos).
     */
    public function disconnect(): void
    {
        $engine = strtolower((string) ($this->config['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

        if ($engine !== 'pdo') {
            return; // Para backend Rust podría añadirse lógica futura.
        }

        if ($this->pdoEngine instanceof PdoEngine) {
            $this->pdoEngine->forceDisconnect();
        }
        $this->pdoEngine = null; // permitir GC
    }

    /**
     * Crea un QueryBuilder para la tabla especificada.
     */
    public function table(string $table, ?string $modelClass = null): QueryBuilder
    {
        return new QueryBuilder($this, $table, $modelClass);
    }

    /**
     * Método público para que QueryBuilder ejecute consultas estructuradas.
     *
     * @param array<string, mixed> $params
     *
     * @return mixed
     */
    public function executeQuery(string $action, array $params)
    {
        return $this->execute($action, $params);
    }

    /**
     * Ejecuta una consulta SQL personalizada.
     *
     * @param array<int, mixed> $bindings
     *
     * @return mixed
     */
    public function exec(string $query, array $bindings = [])
    {
        /** @var mixed $result */
        $result = $this->execute('raw', ['query' => $query, 'bindings' => $bindings]);

        // Normalizar: para sentencias no-SELECT devolver null o [] (tests aceptan null/array vacío)
        if (is_int($result)) {
            return null;
        }

        return $result;
    }

    /**
     * Método alias para compatibilidad con código existente.
     *
     * @param array<int, mixed> $bindings
     *
     * @return mixed
     *
     * @deprecated Usa exec() en su lugar
     */
    public function raw(string $query, array $bindings = [])
    {
        return $this->exec($query, $bindings);
    }

    /**
     * Obtiene el esquema de la base de datos.
     *
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
     * Crea una tabla usando definiciones portables de columnas.
     * columns: lista de arrays con claves: name, type, nullable?, default?, primary?, autoIncrement?
     * options:
     *  - primary_key: string|string[]
     *  - if_not_exists: bool
     *  - engine, charset, collation (MySQL)
     *  - constraints: [
     *      'unique' => [ { name, columns[] }... ],
     *      'foreign' => [ { name, columns[], refTable, refColumns[], onDelete?, onUpdate? } ... ]
     *    ]
     *  - indexes: [ { name, columns[], unique?, using?, where?, concurrently? } ... ].
     */
    /**
     * @param array<int, array<string, mixed>> $columns
     * @param array<string, mixed> $options
     */
    public function schemaCreate(string $table, array $columns, array $options = []): void
    {
        $this->validateFreezeOperation('createTable');
        $driver = strtolower((string) ($this->config['driver'] ?? $this->config['database_type'] ?? 'mysql'));
        $q = fn (string $id): string => $this->quoteIdent($id, $driver);
        $ifNotExists = ! empty($options['if_not_exists']);

        $colSql = [];
        $pkCols = [];
        $sqliteInlinePkUsed = false; // Para SQLite, usamos PK inline solo cuando es INTEGER PRIMARY KEY autoincremental

        /** @var list<ColumnDef> $columns */
        foreach ($columns as $col) {
            $name = (string) ($col['name'] ?? '');
            $type = (string) ($col['type'] ?? 'VARCHAR(255)');

            if ($name === '') {
                continue;
            }
            $nullable = isset($col['nullable']) ? (bool) $col['nullable'] : true;
            $defaultExists = isset($col['default']);
            /** @var mixed $default */
            $default = $col['default'] ?? null;
            $primary = ! empty($col['primary']);
            $auto = ! empty($col['autoIncrement']);

            // Ajustes por dialecto para autoincrement
            $colType = $type;

            if ($auto) {
                if ($driver === 'mysql' || $driver === 'mariadb') {
                    $colType = 'INT';
                } elseif ($driver === 'pgsql' || $driver === 'postgres' || $driver === 'postgresql') {
                    $colType = 'SERIAL';
                } elseif ($driver === 'sqlite') {
                    $colType = 'INTEGER';
                }
            }

            $parts = [$q($name) . ' ' . $colType];

            if ($primary && $driver === 'sqlite' && $auto) {
                // En SQLite la PK autoincremental debe ser exactamente INTEGER PRIMARY KEY
                $parts = [$q($name) . ' INTEGER PRIMARY KEY'];
                $sqliteInlinePkUsed = true;
            } else {
                if (! $nullable) {
                    $parts[] = 'NOT NULL';
                }

                if ($defaultExists) {
                    $parts[] = 'DEFAULT ' . $this->formatDefault($default, $driver);
                }

                if ($auto && ($driver === 'mysql' || $driver === 'mariadb')) {
                    $parts[] = 'AUTO_INCREMENT';
                }

                if ($primary) {
                    $pkCols[] = $q($name);
                }
            }

            $colSql[] = implode(' ', $parts);
        }

        if (! empty($options['primary_key'])) {
            $pk = (array) $options['primary_key'];
            $pkCols = array_map($q, $pk);
        }

        // Para SQLite, permitimos PRIMARY KEY a nivel de tabla cuando no se usó inline (INTEGER PRIMARY KEY)
        if ($pkCols !== [] && ($driver !== 'sqlite' || ($driver === 'sqlite' && ! $sqliteInlinePkUsed))) {
            $colSql[] = 'PRIMARY KEY (' . implode(', ', $pkCols) . ')';
        }

        // Table-level constraints: UNIQUE, FOREIGN KEYS (portables)
        /** @var TableConstraintsDef $constraints */
        $constraints = (array) ($options['constraints'] ?? []);
        /** @var list<UniqueConstraintDef> $uniqueList */
        $uniqueList = (array) ($constraints['unique'] ?? []);

        foreach ($uniqueList as $uq) {
            $cname = isset($uq['name']) ? $q((string) $uq['name']) : null;
            /** @var list<string> $uqCols */
            $uqCols = (array) ($uq['columns'] ?? []);
            $cols = array_map($q, $uqCols);

            if ($cols !== []) {
                $colSql[] = ($cname !== null && $cname !== '' && $cname !== '0' ? ('CONSTRAINT ' . $cname . ' ') : '') . 'UNIQUE (' . implode(', ', $cols) . ')';
            }
        }
        /** @var list<ForeignConstraintDef> $foreignList */
        $foreignList = (array) ($constraints['foreign'] ?? []);

        foreach ($foreignList as $fk) {
            $cname = isset($fk['name']) ? $q((string) $fk['name']) : null;
            /** @var list<string> $fkCols */
            $fkCols = (array) ($fk['columns'] ?? []);
            $cols = array_map($q, $fkCols);
            $refTable = isset($fk['refTable']) ? $q((string) $fk['refTable']) : null;
            /** @var list<string> $fkRefCols */
            $fkRefCols = (array) ($fk['refColumns'] ?? []);
            $refCols = array_map($q, $fkRefCols);

            if ($cols !== [] && $refTable && $refCols !== []) {
                $line = ($cname !== null && $cname !== '' && $cname !== '0' ? ('CONSTRAINT ' . $cname . ' ') : '') . 'FOREIGN KEY (' . implode(', ', $cols) . ') REFERENCES ' . $refTable . ' (' . implode(', ', $refCols) . ')';

                if (! empty($fk['onDelete'])) {
                    $line .= ' ON DELETE ' . strtoupper((string) $fk['onDelete']);
                }

                if (! empty($fk['onUpdate'])) {
                    $line .= ' ON UPDATE ' . strtoupper((string) $fk['onUpdate']);
                }
                $colSql[] = $line;
            }
        }

        $tableIdent = $q($table);
        $createHead = 'CREATE TABLE ' . ($ifNotExists ? 'IF NOT EXISTS ' : '') . $tableIdent;
        $sql = $createHead . ' (' . implode(', ', $colSql) . ')';

        if ($driver === 'mysql' || $driver === 'mariadb') {
            if (! empty($options['engine'])) {
                $sql .= ' ENGINE=' . $options['engine'];
            }

            if (! empty($options['charset'])) {
                $sql .= ' DEFAULT CHARSET=' . $options['charset'];
            }

            if (! empty($options['collation'])) {
                $sql .= ' COLLATE=' . $options['collation'];
            }
        }

        $this->exec($sql);

        // Indexes (post-create portable)
        /** @var list<IndexDef> $indexesList */
        $indexesList = (array) ($options['indexes'] ?? []);

        foreach ($indexesList as $idx) {
            $this->createIndexPortable($table, $idx, $driver);
        }
    }

    /**
     * Modifica una tabla (MVP: soporta add columns). changes: ['add' => [colDefs...]].
     */
    /**
     * @param array<string, mixed> $changes
     */
    public function schemaAlter(string $table, array $changes): void
    {
        $this->validateFreezeOperation('alterTable');
        $driver = strtolower((string) ($this->config['driver'] ?? $this->config['database_type'] ?? 'mysql'));
        $q = fn (string $id): string => $this->quoteIdent($id, $driver);

        $tableIdent = $q($table);
        /** @var AlterChanges $changes */
        /** @var list<ColumnDef> $addCols */
        $addCols = (array) ($changes['add'] ?? []);

        if (! empty($addCols)) {
            $clauses = [];

            foreach ($addCols as $col) {
                $name = (string) ($col['name'] ?? '');
                $type = (string) ($col['type'] ?? 'VARCHAR(255)');

                if ($name === '') {
                    continue;
                }
                $nullable = isset($col['nullable']) ? (bool) $col['nullable'] : true;
                $defaultExists = isset($col['default']);
                /** @var mixed $default */
                $default = $col['default'] ?? null;

                $parts = ['ADD COLUMN ' . $q($name) . ' ' . $type];

                if (! $nullable) {
                    $parts[] = 'NOT NULL';
                }

                if ($defaultExists) {
                    $parts[] = 'DEFAULT ' . $this->formatDefault($default, $driver);
                }
                $clauses[] = implode(' ', $parts);
            }

            if ($clauses !== []) {
                $sql = 'ALTER TABLE ' . $tableIdent . ' ' . implode(', ', $clauses);
                $this->exec($sql);
            }
        }

        // Índices: addIndex / dropIndex
        if (! empty($changes['addIndex'])) {
            /** @var list<IndexDef> $idxList */
            $idxList = (array) $changes['addIndex'];

            foreach ($idxList as $idx) {
                $this->createIndexPortable($table, $idx, $driver);
            }
        }

        if (! empty($changes['dropIndex'])) {
            /** @var list<string> $dropIdx */
            $dropIdx = (array) $changes['dropIndex'];

            foreach ($dropIdx as $idxName) {
                $this->dropIndexPortable($table, (string) $idxName, $driver);
            }
        }

        // Foreign keys: addForeign / dropForeign
        if (! empty($changes['addForeign'])) {
            /** @var list<ForeignConstraintDef> $addForeign */
            $addForeign = (array) $changes['addForeign'];

            foreach ($addForeign as $fk) {
                $name = (string) ($fk['name'] ?? '');
                $cols = (array) ($fk['columns'] ?? []);
                $refTable = (string) ($fk['refTable'] ?? '');
                $refCols = (array) ($fk['refColumns'] ?? []);

                if ($name && $cols && $refTable && $refCols) {
                    $line = 'ALTER TABLE ' . $tableIdent . ' ADD CONSTRAINT ' . $q($name) . ' FOREIGN KEY (' . implode(', ', array_map($q, $cols)) . ') REFERENCES ' . $q($refTable) . ' (' . implode(', ', array_map($q, $refCols)) . ')';

                    if (! empty($fk['onDelete'])) {
                        $line .= ' ON DELETE ' . strtoupper((string) $fk['onDelete']);
                    }

                    if (! empty($fk['onUpdate'])) {
                        $line .= ' ON UPDATE ' . strtoupper((string) $fk['onUpdate']);
                    }
                    // MySQL/PG: OK; SQLite: limitado (aceptamos que pueda fallar)
                    $this->exec($line);
                }
            }
        }

        if (! empty($changes['dropForeign'])) {
            /** @var list<string> $dropForeign */
            $dropForeign = (array) $changes['dropForeign'];

            foreach ($dropForeign as $fkName) {
                $fk = $q((string) $fkName);

                if ($driver === 'mysql' || $driver === 'mariadb') {
                    $sql = 'ALTER TABLE ' . $tableIdent . ' DROP FOREIGN KEY ' . $fk;
                } else {
                    $sql = 'ALTER TABLE ' . $tableIdent . ' DROP CONSTRAINT ' . $fk;
                }
                $this->exec($sql);
            }
        }

        // Rename columns
        if (! empty($changes['rename'])) {
            $clauses = [];
            /** @var list<AlterRenameDef> $renameDefs */
            $renameDefs = (array) $changes['rename'];

            foreach ($renameDefs as $rc) {
                $from = (string) ($rc['from'] ?? '');
                $to = (string) ($rc['to'] ?? '');

                if ($from !== '' && $to !== '') {
                    if ($driver === 'mysql' || $driver === 'mariadb' || $driver === 'pgsql' || $driver === 'postgres' || $driver === 'postgresql') {
                        $clauses[] = 'RENAME COLUMN ' . $q($from) . ' TO ' . $q($to);
                    } elseif ($driver === 'sqlite') {
                        // SQLite soporta RENAME COLUMN (3.25+). Intentar y dejar que falle si no.
                        $clauses[] = 'RENAME COLUMN ' . $q($from) . ' TO ' . $q($to);
                    }
                }
            }

            if ($clauses !== []) {
                $this->exec('ALTER TABLE ' . $tableIdent . ' ' . implode(', ', $clauses));
            }
        }

        // Drop columns
        if (! empty($changes['drop'])) {
            /** @var list<string> $cols */
            $cols = (array) $changes['drop'];
            $clauses = [];

            foreach ($cols as $c) {
                $name = (string) $c;

                if ($name !== '') {
                    $clauses[] = 'DROP COLUMN ' . $q($name);
                }
            }

            if ($clauses !== []) {
                $this->exec('ALTER TABLE ' . $tableIdent . ' ' . implode(', ', $clauses));
            }
        }

        // Modify columns (tipo/null/default)
        if (! empty($changes['modify'])) {
            /** @var list<AlterModifyDef> $mods */
            $mods = (array) $changes['modify'];
            $clauses = [];

            if ($driver === 'mysql' || $driver === 'mariadb') {
                foreach ($mods as $m) {
                    $name = (string) ($m['name'] ?? '');
                    $type = (string) ($m['type'] ?? '');

                    if ($name === '') {
                        continue;
                    }

                    if ($type === '') {
                        continue;
                    }
                    $nullable = isset($m['nullable']) ? (bool) $m['nullable'] : null;
                    $defaultExists = isset($m['default']);
                    /** @var mixed $default */
                    $default = $m['default'] ?? null;
                    $part = 'MODIFY COLUMN ' . $q($name) . ' ' . $type;

                    if ($nullable !== null) {
                        $part .= $nullable ? '' : ' NOT NULL';
                    }

                    if ($defaultExists) {
                        $part .= ' DEFAULT ' . $this->formatDefault($default, $driver);
                    }
                    $clauses[] = $part;
                }

                if ($clauses !== []) {
                    $this->exec('ALTER TABLE ' . $tableIdent . ' ' . implode(', ', $clauses));
                }
            } else {
                // PostgreSQL/SQLite estilo ALTER COLUMN por aspecto
                foreach ($mods as $m) {
                    $name = (string) ($m['name'] ?? '');
                    $type = (string) ($m['type'] ?? '');

                    if ($name === '') {
                        continue;
                    }

                    if ($type === '') {
                        continue;
                    }
                    $nullable = isset($m['nullable']) ? (bool) $m['nullable'] : null;
                    $defaultExists = isset($m['default']);
                    /** @var mixed $default */
                    $default = $m['default'] ?? null;
                    $clauses[] = 'ALTER COLUMN ' . $q($name) . ' TYPE ' . $type;

                    if ($nullable !== null) {
                        $clauses[] = 'ALTER COLUMN ' . $q($name) . ($nullable ? ' DROP NOT NULL' : ' SET NOT NULL');
                    }

                    if ($defaultExists) {
                        if ($default === null) {
                            $clauses[] = 'ALTER COLUMN ' . $q($name) . ' DROP DEFAULT';
                        } else {
                            $clauses[] = 'ALTER COLUMN ' . $q($name) . ' SET DEFAULT ' . $this->formatDefault($default, $driver);
                        }
                    }
                }

                if ($clauses !== []) {
                    $this->exec('ALTER TABLE ' . $tableIdent . ' ' . implode(', ', $clauses));
                }
            }
        }
        // Futuro: rename column, drop column, modify type, add constraint types adicionales.
    }

    /**
     * Elimina una tabla (DROP TABLE [IF EXISTS]).
     */
    public function schemaDrop(string $table, bool $ifExists = true): void
    {
        $this->validateFreezeOperation('dropTable');
        $driver = strtolower((string) ($this->config['driver'] ?? $this->config['database_type'] ?? 'mysql'));
        $q = fn (string $id): string => $this->quoteIdent($id, $driver);
        $sql = 'DROP TABLE ' . ($ifExists ? 'IF EXISTS ' : '') . $q($table);
        $this->exec($sql);
    }

    /**
     * Renombra una tabla a un nuevo nombre (dialecto-aware).
     */
    public function schemaRename(string $from, string $to): void
    {
        $this->validateFreezeOperation('alterTable');
        $driver = strtolower((string) ($this->config['driver'] ?? $this->config['database_type'] ?? 'mysql'));
        $q = fn (string $id): string => $this->quoteIdent($id, $driver);

        if ($driver === 'mysql' || $driver === 'mariadb') {
            $sql = 'RENAME TABLE ' . $q($from) . ' TO ' . $q($to);
        } else {
            // PostgreSQL y SQLite
            $sql = 'ALTER TABLE ' . $q($from) . ' RENAME TO ' . $q($to);
        }
        $this->exec($sql);
    }

    /**
     * Administra el caché interno.
     *
     * @param array<string, mixed> $params
     *
     * @return array<string, mixed>
     */
    public function cache(string $action, array $params = []): array
    {
        $cacheParams = ['action' => $action] + $params;
        $result = $this->execute('cache', $cacheParams);

        return [
            'status' => 'success',
            'data' => $result,
        ];
    }

    /**
     * Inicia una transacción.
     */
    public function beginTransaction(): void
    {
        $this->exec('BEGIN');
    }

    /**
     * Confirma una transacción.
     */
    public function commit(): void
    {
        $this->exec('COMMIT');
    }

    /**
     * Revierte una transacción.
     */
    public function rollBack(): void
    {
        $this->exec('ROLLBACK');
    }

    /**
     * Obtiene la versión actual de VersaORM.
     */
    public function version(): string
    {
        return '1.0.0';
    }

    // Método disconnect unificado se declara más arriba (limpia conexión PDO y GC)

    /**
     * Activa o desactiva el modo freeze global.
     * En modo freeze, se bloquean todas las operaciones DDL que alteran el esquema.
     *
     * @param bool $frozen Estado del modo freeze
     *
     * @throws VersaORMException
     *
     * @return $this
     */
    public function freeze(bool $frozen = true): self
    {
        $this->isFrozen = $frozen;

        // Log de seguridad
        $status = $frozen ? 'ACTIVATED' : 'DEACTIVATED';
        $this->logSecurityEvent(
            "FREEZE_MODE_{$status}",
            [
                'global_freeze' => $frozen,
                'timestamp' => date('Y-m-d H:i:s'),
                'trace' => $this->getDebugStackTrace(),
            ],
        );

        return $this;
    }

    /**
     * Verifica si el modo freeze global está activo.
     */
    public function isFrozen(): bool
    {
        return $this->isFrozen;
    }

    /**
     * Congela un modelo específico.
     *
     * @param string $modelClass Nombre de la clase del modelo
     * @param bool $frozen Estado del freeze para el modelo
     *
     * @return $this
     */
    public function freezeModel(string $modelClass, bool $frozen = true): self
    {
        if ($modelClass === '' || $modelClass === '0') {
            throw new InvalidArgumentException('Model class cannot be empty');
        }

        $this->frozenModels[$modelClass] = $frozen;

        // Log de seguridad
        $status = $frozen ? 'FROZEN' : 'UNFROZEN';
        $this->logSecurityEvent(
            "MODEL_{$status}",
            [
                'model_class' => $modelClass,
                'frozen' => $frozen,
                'timestamp' => date('Y-m-d H:i:s'),
            ],
        );

        return $this;
    }

    /**
     * Verifica si un modelo específico está congelado.
     *
     * @param string $modelClass Nombre de la clase del modelo
     */
    public function isModelFrozen(string $modelClass): bool
    {
        if ($modelClass === '' || $modelClass === '0') {
            throw new InvalidArgumentException('Model class cannot be empty');
        }

        // Verificar freeze global primero
        if ($this->isFrozen) {
            return true;
        }

        return $this->frozenModels[$modelClass] ?? false;
    }

    /**
     * Valida que una operación sea permitida en modo freeze.
     *
     * @param string $operation Nombre de la
     *                          operación
     * @param string|null $modelClass Clase del modelo si aplica
     * @param array<string, mixed> $context Contexto adicional
     *
     * @throws VersaORMException
     */
    public function validateFreezeOperation(string $operation, ?string $modelClass = null, array $context = []): void
    {
        $isDdlOperation = $this->isDdlOperation($operation);
        $isGloballyFrozen = $this->isFrozen();
        $isModelFrozen = $modelClass !== null && $this->isModelFrozen($modelClass);

        // Si es una operación DDL y hay freeze activo, bloquear
        if ($isDdlOperation && ($isGloballyFrozen || $isModelFrozen)) {
            // Log del intento de alteración
            $this->logSecurityEvent(
                'FREEZE_VIOLATION_ATTEMPT',
                [
                    'operation' => $operation,
                    'model_class' => $modelClass,
                    'global_frozen' => $isGloballyFrozen,
                    'model_frozen' => $isModelFrozen,
                    'context' => $context,
                    'timestamp' => date('Y-m-d H:i:s'),
                    'trace' => $this->getDebugStackTrace(),
                ],
            );

            $freezeType = $isGloballyFrozen ? 'global freeze mode' : "model '{$modelClass}' freeze mode";
            $warningMessage = "Operation '{$operation}' blocked by {$freezeType}.";

            // Mostrar advertencia en modo desarrollo
            if ($this->isDebugMode()) {
                $warningMessage .= "\n\nDDL operations are not allowed when freeze mode is active.";
                $warningMessage .= "\nThis is a security measure to prevent schema modifications.";
                $warningMessage .= "\n\nTo allow this operation:";

                if ($isGloballyFrozen) {
                    $warningMessage .= "\n- Disable global freeze: \$orm->freeze(false)";
                } else {
                    $warningMessage .= "\n- Disable model freeze: \$orm->freezeModel('{$modelClass}', false)";
                }
            }

            throw new VersaORMException(
                $warningMessage,
                'FREEZE_VIOLATION',
                null,
                [],
            );
        }
    }

    /**
     * Ejecuta un comando usando la configuración de instancia.
     *
     * @param array<string, mixed> $params
     *
     * @throws VersaORMException
     *
     * @return mixed
     */
    /**
     * Ejecutor interno que decide backend (PDO / Rust).
     *
     * @param array<string,mixed> $params
     *
     * @return mixed
     */
    private function execute(string $action, array $params)
    {
        if ($this->config === []) {
            throw new VersaORMException('Database configuration is not set. Please call setConfig() first.');
        }

        // Validar parámetros de entrada
        $this->validateInput($action, $params);

        // Log de la acción ejecutada
        $this->logDebug("Executing action: {$action}", ['params' => $params]);

        // Elegir backend: por defecto PDO; sólo usar binario si engine === 'rust'
        $engine = strtolower((string) ($this->config['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

        if ($engine === 'pdo' || $engine === '') {
            try {
                // Reutilizar la misma instancia para mantener la conexión viva
                if (! $this->pdoEngine instanceof PdoEngine) {
                    $this->pdoEngine = new PdoEngine($this->config, function (string $message, array $context = []): void {
                        $this->logDebug($message, $context);
                    });
                }

                return $this->pdoEngine->execute($action, $params);
            } catch (Throwable $e) {
                $ex = new VersaORMException(
                    'PDO engine execution error: ' . $e->getMessage(),
                    'PDO_ENGINE_FAILED',
                    $params['query'] ?? null,
                    is_array($params['bindings'] ?? null) ? $params['bindings'] : [],
                    ['action' => $action, 'params' => $this->safeParamsForLog($params)],
                    $this->extractSqlState($e),
                    (int) $e->getCode(),
                    $e instanceof Exception ? $e : null,
                );
                $ex->withDriver($this->config['driver'] ?? null)->withOrigin(__METHOD__);
                // Log inmediato usando ErrorHandler si configurado
                if (class_exists(ErrorHandler::class) && ErrorHandler::isConfigured()) {
                    ErrorHandler::handleException($ex, ['phase' => 'pdo_engine']);
                } else {
                    // fallback mínimo
                    if (function_exists('error_log')) {
                        @error_log('[VersaORM][ERROR] ' . json_encode($ex->toLogArray()));
                    }
                }

                throw $ex;
            }
        }

        // Debug temporal para advanced_sql
        if ($action === 'advanced_sql') {
            // fwrite(STDERR, "=== DEBUG VersaORM::execute advanced_sql ===\n");
            // fwrite(STDERR, "Action: " . $action . "\n");
            // fwrite(STDERR, "Params: " . json_encode($params, JSON_PRETTY_PRINT) . "\n");
        }

        // Debug para raw también
        if ($action === 'raw') {
            // fwrite(STDERR, "=== DEBUG VersaORM::execute raw ===\n");
            // fwrite(STDERR, "Action: " . $action . "\n");
            // fwrite(STDERR, "Params: " . json_encode($params, JSON_PRETTY_PRINT) . "\n");
            // fwrite(STDERR, "Config antes de transformar: " . json_encode($this->config, JSON_PRETTY_PRINT) . "\n");
        }

        try {
            // Convertir configuración para compatibilidad con Rust
            /** @var array{engine?:string,driver?:string,host?:string,port?:int|string,database?:string,database_type?:string,charset?:string,username?:string,password?:string,debug?:bool,options?:array<string,mixed>} $rustConfig */
            $rustConfig = $this->config; // copia superficial para normalizar claves

            if (isset($rustConfig['database_type']) && ! isset($rustConfig['driver'])) {
                $rustConfig['driver'] = $rustConfig['database_type'];
                unset($rustConfig['database_type']);
            }

            $payload = json_encode(
                [
                    // Config normalizada para el binario
                    'config' => $rustConfig,
                    // Acción solicitada
                    'action' => $action,
                    // Parámetros (shape depende de la acción; mantener mixed tipado)
                    'params' => $params,
                    'freeze_state' => [
                        'global_frozen' => $this->isFrozen,
                        'frozen_models' => (object) $this->frozenModels, // Forzar como objeto
                    ],
                ],
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE,
            );

            // Debug: Log the JSON payload being sent to Rust
            // if ($action === 'raw') {
            //     fwrite(STDERR, "=== JSON PAYLOAD ===\n");
            //     fwrite(STDERR, $payload . "\n");
            //     fwrite(STDERR, "=== END PAYLOAD ===\n");
            // }
            error_log('[DEBUG] JSON payload being sent to Rust: ' . $payload);

            // If in debug mode and JSON_DUMP environment variable is set, dump and exit
            if ($this->isDebugMode() && getenv('JSON_DUMP') === 'true') {
                echo "=== JSON PAYLOAD DUMP ===\n";
                echo $payload . "\n";
                echo "========================\n";
                exit(0);
            }
        } catch (JsonException $e) {
            throw new VersaORMException(
                sprintf(
                    'Failed to encode JSON payload: %s. Data contains invalid characters or circular references.',
                    $e->getMessage(),
                ),
                'JSON_ENCODE_ERROR',
            );
        }

        $binaryPath = $this->binaryPath;

        if (! file_exists($binaryPath)) {
            throw new VersaORMException(
                sprintf(
                    'VersaORM binary not found at: %s. Please ensure the binary is compiled and accessible.',
                    $binaryPath,
                ),
                'BINARY_NOT_FOUND',
            );
        }

        // Verificar permisos de ejecución
        if (! is_executable($binaryPath)) {
            throw new VersaORMException(
                sprintf(
                    'VersaORM binary is not executable: %s. Please check file permissions.',
                    $binaryPath,
                ),
                'BINARY_NOT_EXECUTABLE',
            );
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
                'BINARY_EXECUTION_FAILED',
            );
        }

        // Intentar decodificar la respuesta JSON
        try {
            // Limpiar la salida de logs de debug del binario Rust
            $cleanOutput = $this->cleanRustDebugOutput($output);
            /** @var array{status?:string,data?:mixed,error?:array{code?:string,message?:string,details?:array<string,mixed>,sql_state?:string,query?:string,bindings?:array<int,mixed>}}|null $response */
            $response = json_decode($cleanOutput, true, 512, JSON_THROW_ON_ERROR);

            // Debug temporal para advanced_sql
            if ($action === 'advanced_sql') {
                // echo "=== DEBUG Raw Output ===\n";
                // echo "Raw output: " . substr($output, 0, 1000) . "\n";
                // echo "Clean output: " . substr($cleanOutput, 0, 1000) . "\n";
                // echo "Response: " . json_encode($response, JSON_PRETTY_PRINT) . "\n";
            }
        } catch (JsonException $e) {
            throw new VersaORMException(
                sprintf(
                    'Failed to decode JSON response from binary: %s\nRaw output: %s',
                    $e->getMessage(),
                    substr($output, 0, 500), // Limitar la salida para evitar spam
                ),
                'JSON_DECODE_ERROR',
            );
        }

        // Manejar errores del binario
        if (is_array($response) && isset($response['status']) && $response['status'] === 'error') {
            // Construir shape mínima para satisfacer tipado esperado
            /** @var array{status?:string,error?:array{code?:string,message?:string,details?:array<string,mixed>,sql_state?:string,query?:string,bindings?:array<int,mixed>}} $responseShape */
            $responseShape = $response;
            $this->handleBinaryError($responseShape, $action, $params);
        }

        return is_array($response) ? ($response['data'] ?? null) : null;
    }

    /**
     * Sanitiza parámetros para logging (evita exponer credenciales o blobs grandes).
     *
     * @param array<string,mixed> $params
     *
     * @return array<string,mixed>
     */
    private function safeParamsForLog(array $params): array
    {
        $sanitized = [];
        foreach ($params as $k => $v) {
            if (is_string($v)) {
                $sanitized[$k] = (strlen($v) > 500) ? substr($v, 0, 500) . '…' : $v;
            } elseif (is_array($v)) {
                $sanitized[$k] = count($v) > 50 ? array_slice($v, 0, 50) + ['_truncated' => true, '_count' => count($v)] : $v;
            } else {
                $sanitized[$k] = $v;
            }
        }

        return $sanitized;
    }

    /** Extrae SQLSTATE si se puede (PDOException) */
    private function extractSqlState(Throwable $t): ?string
    {
        if ($t instanceof \PDOException && isset($t->errorInfo[0]) && is_string($t->errorInfo[0])) {
            return $t->errorInfo[0];
        }

        return null;
    }

    /**
     * Crea índice portable según driver.
     *
     * @param array<string, mixed> $idx
     */
    private function createIndexPortable(string $table, array $idx, string $driver): void
    {
        $q = fn (string $id): string => $this->quoteIdent($id, $driver);
        /** @var IndexDef $idx */
        $name = (string) ($idx['name'] ?? '');
        /** @var list<IndexColumn> $cols */
        $cols = (array) ($idx['columns'] ?? []);

        if ($name === '' || empty($cols)) {
            return;
        }
        // Validar identificador del índice para evitar inyección por nombre malicioso
        $this->assertSafeIdentifier($name, 'index');
        $unique = ! empty($idx['unique']);
        $using = strtoupper((string) ($idx['using'] ?? ''));
        $where = (string) ($idx['where'] ?? '');
        $ifNotExists = ! empty($idx['if_not_exists']);
        $concurrently = ! empty($idx['concurrently']);

        $sql = 'CREATE ' . ($unique ? 'UNIQUE ' : '') . 'INDEX ';

        if (($driver === 'pgsql' || $driver === 'postgres' || $driver === 'postgresql') && $ifNotExists) {
            $sql .= 'IF NOT EXISTS ';
        }

        if (($driver === 'pgsql' || $driver === 'postgres' || $driver === 'postgresql') && $concurrently) {
            $sql .= 'CONCURRENTLY ';
        }
        $sql .= $q($name) . ' ON ' . $q($table);

        if ($using !== '') {
            // MySQL: USING BTREE/HASH; Postgres: USING GIN/GIST/...
            $sql .= ' USING ' . $using;
        }
        $colsSql = [];

        foreach ($cols as $c) {
            if (is_array($c) && isset($c['raw'])) {
                $colsSql[] = (string) $c['raw'];
            } else {
                $colName = (string) $c;
                // Validar nombres de columnas simples (no RAW)
                $this->assertSafeIdentifier($colName, 'column');
                $colsSql[] = $q($colName);
            }
        }
        $sql .= ' (' . implode(', ', $colsSql) . ')';

        if (($driver === 'pgsql' || $driver === 'postgres' || $driver === 'postgresql') && $where !== '') {
            $sql .= ' WHERE ' . $where;
        }
        $this->exec($sql);
    }

    /** Elimina índice portable según driver. */
    private function dropIndexPortable(string $table, string $indexName, string $driver): void
    {
        $q = fn (string $id): string => $this->quoteIdent($id, $driver);
        $iname = $q($indexName);

        if ($driver === 'mysql' || $driver === 'mariadb') {
            $this->exec('ALTER TABLE ' . $q($table) . ' DROP INDEX ' . $iname);
        } elseif ($driver === 'sqlite') {
            $this->exec('DROP INDEX IF EXISTS ' . $iname);
        } else { // Postgres
            $this->exec('DROP INDEX IF EXISTS ' . $iname);
        }
    }

    /**
     * Quota identificadores según el driver.
     */
    private function quoteIdent(string $ident, string $driver): string
    {
        if ($driver === 'mysql' || $driver === 'mariadb') {
            return '`' . str_replace('`', '``', $ident) . '`';
        }

        // PostgreSQL y SQLite usan comillas dobles
        return '"' . str_replace('"', '""', $ident) . '"';
    }

    /**
     * Valida que un identificador sea seguro (sin inyección ni caracteres peligrosos).
     * Permite: letras, números y guion bajo; debe iniciar con letra o guion bajo.
     * Rechaza: comillas, backticks, punto y coma, comentarios SQL, espacios, paréntesis.
     *
     * @param string $context Contexto (table|column|index|constraint)
     *
     * @throws VersaORMException
     */
    private function assertSafeIdentifier(string $ident, string $context = 'identifier'): void
    {
        $trim = trim($ident);

        // Vacío o diferente tras trim => sospechoso
        if ($trim === '' || $trim !== $ident) {
            throw new VersaORMException("Unsafe {$context} name: '{$ident}'", 'INVALID_IDENTIFIER');
        }
        // Caracteres o patrones peligrosos (chequeo simple por fragmentos)
        $bad = ['`', '"', "'", '(', ')', ';', '.', ' ', "\t", "\n", "\r", '--', '/*', '*/'];

        foreach ($bad as $frag) {
            if (str_contains($ident, $frag)) {
                throw new VersaORMException("Unsafe {$context} name: '{$ident}'", 'INVALID_IDENTIFIER');
            }
        }

        // Solo permitir [A-Za-z_][A-Za-z0-9_]*
        if (preg_match('/^[A-Za-z_]\w*$/', $ident) !== 1) {
            throw new VersaORMException("Invalid {$context} format: '{$ident}'", 'INVALID_IDENTIFIER');
        }
    }

    private function formatDefault(mixed $value, string $driver): string
    {
        if ($value === null) {
            return 'NULL';
        }

        if (is_bool($value)) {
            if ($driver === 'mysql' || $driver === 'mariadb') {
                return $value ? '1' : '0';
            }

            return $value ? 'TRUE' : 'FALSE';
        }

        if (is_numeric($value)) {
            return (string) $value;
        }

        // Cadenas: detectar funciones/constantes temporales conocidas
        if (is_string($value)) {
            $v = trim($value);

            if (preg_match('/^(CURRENT_TIMESTAMP(?:\(\))?|NOW\(\)|CURRENT_DATE|CURRENT_TIME)$/i', $v) === 1) {
                return strtoupper($v);
            }
        }

        // Por defecto, comillar
        return '\'' . str_replace('\'', '\'\'', (string) $value) . '\'';
    }

    private function isDdlOperation(string $operation): bool
    {
        $ddlOperations = [
            'createTable',
            'dropTable',
            'alterTable',
            'addColumn',
            'dropColumn',
            'modifyColumn',
            'renameColumn',
            'addIndex',
            'dropIndex',
            'addForeignKey',
            'dropForeignKey',
            'createIndex',
            'renameTable',
            'truncateTable',
            'rawDDL', // Consultas DDL raw
            // Operaciones de esquema que modifican estructura
            'create_table',
            'drop_table',
            'alter_table',
            'add_column',
            'drop_column',
            'modify_column',
            'rename_column',
            'add_index',
            'drop_index',
            'create_index',
            'drop_index',
            'add_foreign_key',
            'drop_foreign_key',
            'rename_table',
            'truncate_table',
        ];

        return in_array(strtolower($operation), array_map('strtolower', $ddlOperations), true);
    }

    /**
     * Verifica si una consulta SQL raw es una operación DDL.
     *
     * @param string $query La consulta SQL a verificar
     *
     * @return bool True si es una operación DDL, false en caso contrario
     */
    private function isRawQueryDDL(string $query): bool
    {
        // Normalizar la consulta: eliminar espacios en blanco y convertir a minúsculas
        $normalizedQuery = strtolower(trim($query));

        // Patrones DDL comunes
        $ddlPatterns = [
            '/^create\s+(table|index|view|database|schema|trigger|procedure|function)/',
            '/^drop\s+(table|index|view|database|schema|trigger|procedure|function)/',
            '/^alter\s+(table|index|view|database|schema)/',
            '/^truncate\s+table/',
            '/^rename\s+table/',
            '/^comment\s+on/',
        ];

        foreach ($ddlPatterns as $pattern) {
            if (preg_match($pattern, $normalizedQuery)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Obtiene el directorio de logs configurado.
     */
    private function getLogDirectory(): string
    {
        // Usar log_path de la configuración si está disponible
        if (isset($this->config['log_path']) && ! empty($this->config['log_path'])) {
            return rtrim($this->config['log_path'], '/\\');
        }

        // Fallback al directorio por defecto
        return __DIR__ . '/logs';
    }

    /**
     * Registra eventos de seguridad relacionados con el modo freeze.
     *
     * @param array<string, mixed> $data
     */
    private function logSecurityEvent(string $event, array $data): void
    {
        try {
            $logDir = $this->getLogDirectory();

            if (! is_dir($logDir) && (! mkdir($logDir, 0755, true) && ! is_dir($logDir))) {
                throw new RuntimeException(sprintf('Directory "%s" was not created', $logDir));
            }

            $securityLogFile = $logDir . '/php-security-' . date('Y-m-d') . '.log';
            $timestamp = date('Y-m-d H:i:s');

            $logEntry = sprintf(
                "[%s] [SECURITY] [%s] %s\n",
                $timestamp,
                $event,
                json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT),
            );

            file_put_contents($securityLogFile, $logEntry, FILE_APPEND | LOCK_EX);

            // También registrar en el log principal si el debug está habilitado
            if ($this->isDebugMode()) {
                $this->logDebug("Security Event: {$event}", $data);
            }
        } catch (Throwable) {
            // Silenciar errores de logging para no interferir con la operación principal
        }
    }

    /**
     * Valida los parámetros de entrada antes de ejecutar comandos.
     *
     * @param array<string, mixed> $params
     *
     * @throws VersaORMException
     */
    private function validateInput(string $action, array $params): void
    {
        // Validar que la acción no esté vacía
        if ($action === '' || $action === '0') {
            throw new VersaORMException('Action parameter cannot be empty.');
        }

        // Validar acciones conocidas
        $validActions = [
            'query',
            'raw',
            'schema',
            'cache',
            'insert',
            'insertGetId',
            'update',
            'delete',
            'query_plan',
            'explain_plan',
            'upsert',
            'upsertMany',
            'replaceInto',
            'replaceIntoMany',
            'insertMany',
            'updateMany',
            'deleteMany',
            'advanced_sql',
        ];

        if (! in_array($action, $validActions, true)) {
            throw new VersaORMException(
                sprintf(
                    'Invalid action: %s. Valid actions are: %s',
                    $action,
                    implode(', ', $validActions),
                ),
            );
        }

        // Validaciones específicas por acción
        switch ($action) {
            case 'raw':
                if (! isset($params['query']) || ! is_string($params['query'])) {
                    throw new VersaORMException('Raw action requires a valid query string.', 'INVALID_QUERY');
                }

                if (strlen($params['query']) > 1000000) { // 1MB limit
                    throw new VersaORMException('Query string exceeds maximum length (1MB).', 'QUERY_TOO_LONG');
                }

                // Validar freeze para consultas DDL raw
                if ($this->isRawQueryDDL($params['query'])) {
                    $this->validateFreezeOperation('rawDDL', null, ['query' => $params['query']]);
                }
                break;

            case 'schema':
                if (! isset($params['subject']) || ! is_string($params['subject'])) {
                    throw new VersaORMException('Schema action requires a valid subject.', 'INVALID_SCHEMA_SUBJECT');
                }
                break;

            case 'cache':
                if (! isset($params['action']) || ! is_string($params['action'])) {
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
     * @param array<string, mixed> $params
     *
     * @throws VersaORMException
     */
    /**
     * @param array{status?:string,error?:array{code?:string,message?:string,details?:array<string,mixed>,sql_state?:string,query?:string,bindings?:array<int,mixed>}} $response
     * @param array<string,mixed> $params
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

        if ($sqlQuery !== null && $sqlQuery !== '' && $sqlQuery !== '0') {
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

            if ($where !== []) {
                $whereDesc = [];

                foreach ($where as $w) {
                    if (is_array($w) && (($w['operator'] ?? null) === 'RAW') && isset($w['value']) && is_array($w['value'])) {
                        // Manejo especial para whereRaw
                        $rawSql = isset($w['value']['sql']) && is_string($w['value']['sql']) ? $w['value']['sql'] : 'unknown';
                        $rawBindings = isset($w['value']['bindings']) && is_array($w['value']['bindings']) ? $w['value']['bindings'] : [];
                        $bindingsStr = $rawBindings === [] ? '' : ' [bindings: ' . json_encode($rawBindings) . ']';
                        $whereDesc[] = "RAW({$rawSql}){$bindingsStr}";
                    } elseif (is_array($w) && isset($w['value']) && is_array($w['value'])) {
                        $value = '[' . implode(',', $w['value']) . ']';
                        $whereDesc[] = "{$w['column']} {$w['operator']} {$value}";
                    } elseif (is_array($w)) {
                        $value = (string) ($w['value'] ?? '');
                        $whereDesc[] = "{$w['column']} {$w['operator']} {$value}";
                    }
                }
                $query .= ', where=[' . implode(' AND ', $whereDesc) . ']';
            }

            if ($orderBy !== [] && isset($orderBy[0]) && is_array($orderBy[0])) {
                $query .= ", orderBy={$orderBy[0]['column']} {$orderBy[0]['direction']}";
            }

            if ($limit !== 0 && ($limit !== '' && $limit !== '0')) {
                $query .= ', limit=' . $limit;
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
                $bindings,
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
            $sqlState,
        );
    }

    /**
     * Construye un mensaje de error detallado.
     *
     * @param array<string, mixed> $errorDetails
     * @param array<int, mixed> $bindings
     */
    private function buildDetailedErrorMessage(
        string $errorCode,
        string $errorMessage,
        array $errorDetails,
        ?string $sqlState,
        string $action,
        ?string $query,
        array $bindings = [],
    ): string {
        $message = sprintf('VersaORM Error [%s]: %s', $errorCode, $errorMessage);

        // Añadir la consulta y parámetros al mensaje de error si están disponibles
        if ($query !== null) {
            $message .= sprintf('\n\nQuery: %s', $query);
        }

        if ($bindings !== []) {
            $message .= sprintf('\n\nBindings: %s', json_encode($bindings));
        }

        if ($sqlState !== null && $sqlState !== '' && $sqlState !== '0') {
            $message .= sprintf('\nSQL State: %s', $sqlState);
        }

        // Agregar sugerencias basadas en el tipo de error
        $suggestions = $this->getErrorSuggestions($errorMessage);

        if ($suggestions !== []) {
            $message .= '\n\nSuggestions:';

            foreach ($suggestions as $suggestion) {
                $message .= '\n- ' . $suggestion;
            }
        }

        // Agregar detalles adicionales si están disponibles
        if ($errorDetails !== []) {
            $message .= '\n\nDetails:';

            foreach ($errorDetails as $key => $value) {
                $message .= sprintf('\n- %s: %s', $key, is_scalar($value) ? (string) $value : json_encode($value));
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
     */
    private function buildSimpleErrorMessage(string $errorCode, string $errorMessage): string
    {
        return sprintf('Database Error [%s]: %s', $errorCode, $errorMessage);
    }

    /**
     * Verifica si está habilitado el modo debug.
     */
    private function isDebugMode(): bool
    {
        return isset($this->config['debug']) && $this->config['debug'];
    }

    /**
     * Obtiene el stack trace para modo debug.
     */
    private function getDebugStackTrace(): string
    {
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
        $traceStr = '';

        foreach ($trace as $i => $frame) {
            if (isset($frame['file'], $frame['line'])) {
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
     * Registra información de debug en log.
     *
     * @param array<string, mixed> $context
     */
    private function logDebug(string $message, array $context = []): void
    {
        if (! $this->isDebugMode()) {
            return;
        }

        try {
            $logDir = $this->getLogDirectory();

            if (! is_dir($logDir) && (! mkdir($logDir, 0755, true) && ! is_dir($logDir))) {
                throw new RuntimeException(sprintf('Directory "%s" was not created', $logDir));
            }

            $logFile = $logDir . '/php-' . date('Y-m-d') . '.log';
            $timestamp = date('Y-m-d H:i:s');

            $logEntry = sprintf(
                "[%s] [PHP] [DEBUG] %s\n",
                $timestamp,
                $message,
            );

            if ($context !== []) {
                $logEntry .= sprintf(
                    "[%s] [PHP] [CONTEXT] %s\n",
                    $timestamp,
                    json_encode($context, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT),
                );
            }

            file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
        } catch (Throwable) {
            // Silenciar errores de logging para no interferir con la ejecución principal
        }
    }

    /**
     * Registra el error en log si está en modo debug.
     *
     * @param array<int, mixed> $bindings
     */
    private function logError(string $errorCode, string $errorMessage, ?string $query, array $bindings, string $fullMessage): void
    {
        if (! $this->isDebugMode()) {
            return;
        }

        try {
            $logDir = $this->getLogDirectory();

            if (! is_dir($logDir) && (! mkdir($logDir, 0755, true) && ! is_dir($logDir))) {
                throw new RuntimeException(sprintf('Directory "%s" was not created', $logDir));
            }

            // Usar archivo con fecha actual (YYYY-MM-DD.log)
            $logFile = $logDir . '/php-' . date('Y-m-d') . '.log';
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
                str_replace("\n", ' | ', $fullMessage),
            );

            file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);

            // Limpiar logs antiguos (mantener solo 7 días)
            $this->cleanOldLogs($logDir);
        } catch (Throwable) {
            // Silenciar errores de logging para no interferir con el error principal
        }
    }

    /**
     * Limpia archivos de log antiguos (más de 7 días).
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
                if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $filename) === 1) {
                    $fileDate = strtotime($filename);

                    if ($fileDate !== false && $sevenDaysAgo !== false && $fileDate < $sevenDaysAgo) {
                        unlink($file);
                    }
                }
            }
        } catch (Throwable) {
            // Silenciar errores de limpieza de logs
        }
    }

    /**
     * Proporciona sugerencias basadas en el tipo de error.
     *
     * @return array<int, string>
     */
    private function getErrorSuggestions(string $errorMessage): array
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
     * @param array<int, string> $visited
     *
     * @throws VersaORMException
     */
    private function checkCircularReferences(mixed $data, array &$visited = []): void
    {
        // Solo verificar objetos reales, no arrays convertidos
        if (is_object($data)) {
            $hash = spl_object_hash($data);

            if (in_array($hash, $visited, true)) {
                throw new VersaORMException('Circular reference detected in parameters.');
            }
            $visited[] = $hash;

            if (method_exists($data, 'toArray')) {
                $this->checkCircularReferences($data->toArray(), $visited);
            } elseif ($data instanceof Traversable) {
                foreach ($data as $value) {
                    $this->checkCircularReferences($value, $visited);
                }
            }

            array_pop($visited);
        } elseif (is_array($data)) {
            // Para arrays, solo verificar si tienen referencias reales de objetos
            foreach ($data as $value) {
                if (is_object($value) || (is_array($value) && $value !== [])) {
                    $this->checkCircularReferences($value, $visited);
                }
            }
        }
    }

    /**
     * Ejecuta el binario usando un archivo temporal para evitar problemas de escape.
     */
    private function executeBinaryWithTempFile(string $binaryPath, string $payload): ?string
    {
        // Para el mock de PowerShell, pasamos el payload directamente via stdin
        if (str_contains($binaryPath, 'versaorm_core.bat')) {
            // Usar pipes para pasar JSON via stdin
            $descriptorspec = [
                0 => ['pipe', 'r'],  // stdin
                1 => ['pipe', 'w'],  // stdout
                2 => ['pipe', 'w'],   // stderr
            ];

            $process = proc_open($binaryPath, $descriptorspec, $pipes);

            if (! is_resource($process)) {
                throw new VersaORMException('Failed to start PowerShell mock process.', 'PROCESS_START_ERROR');
            }

            try {
                // Escribir payload a stdin
                fwrite($pipes[0], $payload);
                fclose($pipes[0]);

                // Leer respuesta desde stdout
                $output = stream_get_contents($pipes[1]);
                fclose($pipes[1]);

                // Leer errores desde stderr
                $errors = stream_get_contents($pipes[2]);
                fclose($pipes[2]);

                // Esperar a que termine el proceso
                $returnCode = proc_close($process);

                if ($returnCode !== 0 && ! ($errors === '' || $errors === '0' || $errors === false)) {
                    throw new VersaORMException('PowerShell mock error: ' . $errors, 'MOCK_EXECUTION_ERROR');
                }

                return $output !== false ? $output : null;
            } catch (Exception $e) {
                // Cerrar recursos en caso de error
                foreach ($pipes as $pipe) {
                    if (is_resource($pipe)) {
                        fclose($pipe);
                    }
                }
                proc_close($process);

                throw $e;
            }
        }

        // Comportamiento original para binarios reales
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
            $command = sprintf('%s %s 2>&1', escapeshellarg($binaryPath), escapeshellarg("@{$tempFile}"));

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
     */
    private function setBinaryPath(): void
    {
        $binaryDir = __DIR__ . '/binary';

        $this->binaryPath = match (PHP_OS_FAMILY) {
            'Windows' => $binaryDir . '/versaorm_cli.exe',
            'Linux' => $binaryDir . '/versaorm_cli_linux',
            'Darwin' => $binaryDir . '/versaorm_cli_darwin',
            default => $binaryDir . '/versaorm_cli_linux',
        };
    }

    /**
     * Verifica la existencia del binario de Rust.
     *
     * @throws RuntimeException
     */
    private function checkRustBinary(): void
    {
        if (! file_exists($this->binaryPath)) {
            $osName = strtolower(PHP_OS_FAMILY);
            $expectedName = 'versaorm_cli_{$osName}' . (PHP_OS_FAMILY === 'Windows' ? '.exe' : '');

            throw new RuntimeException(
                "VersaORM binary not found at: {
                {$this->binaryPath}}
\n\n" .
                    "Expected binary name: {
                    {$expectedName}}
\n\n" .
                    "To fix this:\n" .
                    "1. Compile the binary: cd versaorm_cli && cargo build --release\n" .
                    "2. Copy to: src/binary/{
                    {$expectedName}}\n\n" .
                    'For cross-compilation, see src/binary/README.md',
            );
        }

        // En sistemas Unix, verificar permisos de ejecución
        if (PHP_OS_FAMILY !== 'Windows' && ! is_executable($this->binaryPath)) {
            throw new RuntimeException(
                "VersaORM binary exists but is not executable: {
                {$this->binaryPath}}
\n\n" .
                    "Fix with: chmod +x {
                    {$this->binaryPath}}",
            );
        }
    }

    /**
     * Limpia la salida del binario Rust eliminando logs de debug
     * para extraer solo el JSON válido.
     *
     * @param string $output Salida cruda del binario
     *
     * @return string JSON limpio
     */
    private function cleanRustDebugOutput(string $output): string
    {
        // Si ya es JSON válido, devolverlo sin modificar
        if (json_decode($output) !== null) {
            return $output;
        }

        // Buscar el inicio del JSON válido (primera llave de apertura)
        $jsonStart = strpos($output, '{');

        if ($jsonStart === false) {
            // Si no hay JSON, devolver la salida original
            return $output;
        }

        // Extraer desde la primera llave hasta el final
        $jsonCandidate = substr($output, $jsonStart);

        // Buscar el final del JSON válido (última llave de cierre balanceada)
        $braceCount = 0;
        $jsonEnd = -1;
        $length = strlen($jsonCandidate);

        for ($i = 0; $i < $length; $i++) {
            if ($jsonCandidate[$i] === '{') {
                $braceCount++;
            } elseif ($jsonCandidate[$i] === '}') {
                $braceCount--;

                if ($braceCount === 0) {
                    $jsonEnd = $i;
                    break;
                }
            }
        }

        if ($jsonEnd === -1) {
            // Si no se pudo balancear, devolver desde el primer '{'
            return $jsonCandidate;
        }

        // Devolver solo el JSON válido
        $cleanJson = substr($jsonCandidate, 0, $jsonEnd + 1);

        // Log de debug si está habilitado
        if ($this->config['debug'] ?? false) {
            error_log('[VersaORM] Cleaned Rust debug output. Original length: ' . strlen($output) . ', Clean length: ' . strlen($cleanJson));
        }

        return $cleanJson;
    }
}
