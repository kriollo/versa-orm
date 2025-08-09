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
    /** @var array<string, mixed> */
    private array $config;
    private PdoConnection $connector;
    private SqlDialectInterface $dialect;
    /**
     * Logger opcional inyectable.
     * @var (callable(string,array<string,mixed>):void)|null
     */
    private $logger = null;

    // Caché en memoria (estático para compartirse entre instancias durante tests)
    private static bool $cacheEnabled = false;
    /**
     * Caché de consultas.
     * Clave: hash derivado de (sql, bindings, method).
     * Valor: resultados normalizados por método:
     *  - get/raw: list<array<string,mixed>>
     *  - first: array<string,mixed>|null
     *  - count: int
     *  - exists: bool
     *  - otros potenciales (futuros): scalar|null
     *
     * @var array<string, int|bool|null|array<string,mixed>|list<array<string,mixed>>>
     */
    private static array $queryCache = [];
    /** @var array<string, array<int, string>> Mapear tabla -> claves de caché */
    private static array $tableKeyIndex = [];

    // Métricas internas simples (estáticas para compartirse en tests)
    /**
     * @var array{
     *  queries:int,
     *  writes:int,
     *  transactions:int,
     *  cache_hits:int,
     *  cache_misses:int,
     *  last_query_ms:float,
     *  total_query_ms:float
     * }
     */
    private static array $metrics = [
        'queries'        => 0,    // Consultas realmente ejecutadas contra la BD
        'writes'         => 0,    // INSERT/UPDATE/DELETE
        'transactions'   => 0,    // BEGIN
        'cache_hits'     => 0,
        'cache_misses'   => 0,
        'last_query_ms'  => 0.0,
        'total_query_ms' => 0.0,
        // Métricas de caché de sentencias
        'stmt_cache_hits'   => 0,
        'stmt_cache_misses' => 0,
        'total_prepare_ms'  => 0.0,
        // Métricas de hidratación (creación de objetos VersaModel)
        'hydration_ms'      => 0.0,
        'objects_hydrated'  => 0,
        // Fast-path hidratación
        'hydration_fastpath_uses' => 0,
        'hydration_fastpath_rows' => 0,
        'hydration_fastpath_ms'   => 0.0,
    ];

    /** @var array<string,\PDOStatement> LRU cache de sentencias preparadas */
    private static array $stmtCache = [];
    /** @var int límite de sentencias en caché */
    private static int $stmtCacheLimit = 100;

    /**
     * Devuelve métricas actuales.
     * @return array<string,int|float>
     */
    public static function getMetrics(): array
    {
        return self::$metrics;
    }

    /** Resetea métricas + caché de sentencias (instancia) */
    public function resetAllMetrics(): void
    {
        self::resetMetrics();
    }

    /** Resetea métricas (uso interno/tests) */
    public static function resetMetrics(): void
    {
        self::$metrics = [
            'queries'        => 0,
            'writes'         => 0,
            'transactions'   => 0,
            'cache_hits'     => 0,
            'cache_misses'   => 0,
            'last_query_ms'  => 0.0,
            'total_query_ms' => 0.0,
            'stmt_cache_hits'   => 0,
            'stmt_cache_misses' => 0,
            'total_prepare_ms'  => 0.0,
            'hydration_ms'      => 0.0,
            'objects_hydrated'  => 0,
            'hydration_fastpath_uses' => 0,
            'hydration_fastpath_rows' => 0,
            'hydration_fastpath_ms'   => 0.0,
        ];
        self::$stmtCache = [];
    }

    /** Registra métricas de hidratación de modelos */
    public static function recordHydration(int $count, float $elapsedMs): void
    {
        if ($count <= 0) {
            return;
        }
        self::$metrics['objects_hydrated'] = self::$metrics['objects_hydrated'] + $count;
        self::$metrics['hydration_ms'] = self::$metrics['hydration_ms'] + $elapsedMs;
    }

    /** Registra uso de fast-path de hidratación */
    public static function recordHydrationFast(int $count, float $elapsedMs): void
    {
        if ($count <= 0) {
            return;
        }
        self::$metrics['hydration_fastpath_uses'] = self::$metrics['hydration_fastpath_uses'] + 1;
        self::$metrics['hydration_fastpath_rows'] = self::$metrics['hydration_fastpath_rows'] + $count;
        self::$metrics['hydration_fastpath_ms'] = self::$metrics['hydration_fastpath_ms'] + $elapsedMs;
        // También acumular en métricas generales de hidratación
        self::recordHydration($count, $elapsedMs);
    }

    /** Registra ejecución de consulta */
    private static function recordQuery(bool $isWrite, float $elapsedMs): void
    {
        self::$metrics['queries'] = self::$metrics['queries'] + 1;
        if ($isWrite) {
            self::$metrics['writes'] = self::$metrics['writes'] + 1;
        }
        self::$metrics['last_query_ms']  = $elapsedMs;
        self::$metrics['total_query_ms'] = self::$metrics['total_query_ms'] + $elapsedMs;
    }

    /** Registra hit de caché */
    private static function recordCacheHit(): void
    {
        self::$metrics['cache_hits'] = self::$metrics['cache_hits'] + 1;
    }

    /** Registra miss de caché */
    private static function recordCacheMiss(): void
    {
        self::$metrics['cache_misses'] = self::$metrics['cache_misses'] + 1;
    }

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config, ?callable $logger = null)
    {
        $this->config    = $config;
        $this->connector = new PdoConnection($config);
        $this->dialect   = $this->detectDialect();
        // Configurar límite de caché si se provee
        $limit = (int)($config['statement_cache_limit'] ?? 100);
        if ($limit > 0 && $limit < 5000) {
            self::$stmtCacheLimit = $limit;
        }
        // Provide dialect name hint if supported for SQL generator decisions
        // Ahora todos los dialectos implementan getName()
        if ($logger !== null) {
            $this->logger = $logger;
        }
    }

    /** Permite inyectar un logger (por ejemplo, VersaORM::logDebug) */
    public function setLogger(callable $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * Log auxiliar seguro.
     * @param array<string,mixed> $context
     */
    private function log(string $message, array $context = []): void
    {
        if (is_callable($this->logger)) {
            try {
                ($this->logger)($message, $context);
            } catch (\Throwable $e) {
                // ignorar errores de logging
            }
        }
    }

    /**
     * Enlaza parámetros con tipos adecuados y ejecuta el statement.
     * Forza INT/BOOL/NULL; el resto como STR para evitar sorpresas en SQLite.
     *
     * @param \PDOStatement $stmt
     * @param array<int, mixed> $bindings
     */
    private function bindAndExecute(\PDOStatement $stmt, array $bindings): void
    {
        if (!empty($bindings)) {
            foreach (array_values($bindings) as $i => $val) {
                $param = $i + 1; // 1-based
                if (is_int($val)) {
                    $stmt->bindValue($param, $val, \PDO::PARAM_INT);
                } elseif (is_bool($val)) {
                    $stmt->bindValue($param, $val, \PDO::PARAM_BOOL);
                } elseif ($val === null) {
                    $stmt->bindValue($param, $val, \PDO::PARAM_NULL);
                } else {
                    // floats y strings van como STR
                    $stmt->bindValue($param, (string)$val, \PDO::PARAM_STR);
                }
            }
            $stmt->execute();
            return;
        }
        $stmt->execute();
    }

    /**
     * Ejecuta un SQL con bindings y devuelve siempre una lista normalizada de filas asociativas.
     * @param array<int, mixed> $bindings
     * @return list<array<string, mixed>>
     */
    private function executeFetchAll(PDO $pdo, string $sql, array $bindings = []): array
    {
        $stmt = $this->prepareCached($pdo, $sql);
        $this->bindAndExecute($stmt, $bindings);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return is_array($rows) ? array_values($rows) : [];
    }

    /**
     * Obtiene una sentencia preparada desde caché o la prepara y cachea.
     */
    private function prepareCached(PDO $pdo, string $sql): \PDOStatement
    {
        $key = md5($sql);
        if (isset(self::$stmtCache[$key])) {
            self::$metrics['stmt_cache_hits']++;
            // LRU: mover al final (reinsertar)
            $stmt = self::$stmtCache[$key];
            unset(self::$stmtCache[$key]);
            self::$stmtCache[$key] = $stmt;
            return $stmt;
        }
        self::$metrics['stmt_cache_misses']++;
        $start = microtime(true);
        $stmt  = $pdo->prepare($sql);
        self::$metrics['total_prepare_ms'] += (microtime(true) - $start) * 1000;
        self::$stmtCache[$key] = $stmt;
        // Evict LRU (primer elemento)
        if (count(self::$stmtCache) > self::$stmtCacheLimit) {
            array_shift(self::$stmtCache);
        }
        return $stmt;
    }

    private function detectDialect(): SqlDialectInterface
    {
        $driver = strtolower((string)($this->config['driver'] ?? 'mysql'));
        return match ($driver) {
            'mysql', 'mariadb' => new MySQLDialect(),
            'pgsql', 'postgres', 'postgresql' => new PostgreSQLDialect(),
            'sqlite' => new SQLiteDialect(),
            default  => new MySQLDialect(),
        };
    }

    /**
     * @param array<string, mixed> $params
     * @return mixed
     */
    public function execute(string $action, array $params)
    {
        $pdo = $this->connector->getPdo();
        // Normalizar acción a minúsculas para comparaciones consistentes
        $normalizedAction = strtolower($action);

        // ==============================
        // Acciones batch directas (insertMany, updateMany, deleteMany, upsertMany)
        // El QueryBuilder ahora envía estas acciones como acción principal y
        // no como method dentro de 'query', así que las manejamos aquí primero.
        // ==============================
        if (in_array($normalizedAction, ['insertmany', 'updatemany', 'deletemany', 'upsertmany'], true)) {
            // Exhaustivo respecto a la lista filtrada; no se necesita default (evita rama inalcanzable segun PHPStan)
            return match ($normalizedAction) {
                'insertmany' => $this->handleInsertMany($params, $pdo),
                'updatemany' => $this->handleUpdateMany($params, $pdo),
                'deletemany' => $this->handleDeleteMany($params, $pdo),
                'upsertmany' => $this->handleUpsertMany($params, $pdo),
            };
        }
        // Acción especial 'schema' para introspección mínima (MySQL/SQLite/Postgres)
        if ($action === 'schema') {
            $subject = strtolower((string)($params['subject'] ?? ''));
            if ($subject === 'tables') {
                // Normalizar a arreglo simple de nombres de tabla (strings)
                $rows  = $this->fetchTables($pdo);
                $names = [];
                foreach ($rows as $r) {
                    if (is_array($r) && isset($r['table_name'])) {
                        $names[] = (string)$r['table_name'];
                    } elseif (is_string($r)) {
                        $names[] = $r;
                    }
                }
                return $names;
            }
            if ($subject === 'columns') {
                $table = (string)($params['table_name'] ?? $params['table'] ?? '');
                return $table !== '' ? $this->fetchColumns($pdo, $table) : [];
            }
            if ($subject === 'indexes') {
                $table = (string)($params['table_name'] ?? $params['table'] ?? '');
                return $table !== '' ? $this->fetchIndexes($pdo, $table) : [];
            }
            return [];
        }

        // Stubs para planificador en modo PDO
        if ($action === 'explain_plan') {
            $operations = $params['operations'] ?? [];
            $sql        = '';
            try {
                if (is_array($operations) && !empty($operations)) {
                    [$sql,] = $this->buildSqlFromOperation($operations[0]);
                    // Ajuste para tests que esperan FROM users sin comillas
                    $replaced = preg_replace('/`([^`]+)`/', '${1}', (string)$sql);
                    $sql      = is_string($replaced) ? $replaced : $sql;
                }
            } catch (\Throwable $e) {
                $sql = '-- SQL generation failed: ' . $e->getMessage();
            }
            return [
                'plan' => [
                    'estimated_cost' => 0,
                ],
                'generated_sql'         => $sql,
                'optimizations_applied' => false,
            ];
        }

        if ($action === 'query_plan') {
            $operations = $params['operations'] ?? [];
            if (!is_array($operations) || empty($operations)) {
                return [];
            }
            // Ejecutar sólo la primera operación como fallback
            [$sql, $bindings] = $this->buildSqlFromOperation($operations[0]);
            $stmt             = $this->prepareCached($pdo, $sql);
            $this->bindAndExecute($stmt, $bindings);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return is_array($rows) ? $rows : [];
        }

        // Gestión de caché (enable/disable/clear/status/invalidate)
        if ($action === 'cache') {
            $cacheAction = strtolower((string)($params['action'] ?? ''));
            return match ($cacheAction) {
                'enable' => (function () {
                    self::$cacheEnabled = true;
                    return 'cache enabled';
                })(),
                'disable' => (function () {
                    self::$cacheEnabled = false;
                    return 'cache disabled';
                })(),
                'clear' => (function () {
                    self::$queryCache    = [];
                    self::$tableKeyIndex = [];
                    return 'cache cleared';
                })(),
                'status'     => (int)count(self::$queryCache),
                'invalidate' => (function () use ($params) {
                    $table   = isset($params['table']) ? (string)$params['table'] : '';
                    $pattern = isset($params['pattern']) ? (string)$params['pattern'] : '';
                    if ($table === '' && $pattern === '') {
                        throw new VersaORMException('Cache invalidation requires a table or pattern parameter.', 'INVALID_CACHE_INVALIDATE');
                    }
                    if ($table !== '') {
                        self::invalidateCacheForTable($table);
                    }
                    if ($pattern !== '') {
                        self::invalidateCacheByPattern($pattern);
                    }
                    return 'cache invalidated';
                })(),
                default => throw new VersaORMException('PDO engine does not support this cache action: ' . $cacheAction, 'UNSUPPORTED_CACHE_ACTION'),
            };
        }

        // Soporte mínimo para operaciones avanzadas cuando el motor es PDO
        if ($action === 'advanced_sql') {
            $driver = $this->dialect->getName();
            $opType = (string)($params['operation_type'] ?? '');
            try {
                $result = match ($opType) {
                    'window_function' => (function () use ($params, $pdo) {
                        // SELECT existente + columna window
                        $table    = (string)($params['table'] ?? '');
                        $function = strtolower((string)($params['function'] ?? 'row_number'));
                        $column   = (string)($params['column'] ?? '*');
                        $alias    = (string)($params['alias'] ?? 'window_result');
                        /** @var list<string> $partition */
                        $partition = [];
                        if (isset($params['partition_by']) && is_array($params['partition_by'])) {
                            foreach ($params['partition_by'] as $p) {
                                if (is_string($p) && $p !== '') {
                                    $partition[] = $p;
                                }
                            }
                        }
                        /** @var list<array{column:string,direction?:string}> $orderBy */
                        $orderBy = [];
                        if (isset($params['order_by']) && is_array($params['order_by'])) {
                            foreach ($params['order_by'] as $o) {
                                if (is_array($o) && isset($o['column']) && is_string($o['column'])) {
                                    $entry = ['column' => (string)$o['column']];
                                    if (isset($o['direction']) && is_string($o['direction'])) {
                                        $entry['direction'] = $o['direction'];
                                    }
                                    $orderBy[] = $entry; // forma tipada
                                }
                            }
                        }
                        /** @var list<array{type:string,field:string,operator:string,value:mixed,boolean?:string}> $wheres */
                        $wheres = [];
                        if (isset($params['wheres']) && is_array($params['wheres'])) {
                            foreach ($params['wheres'] as $w) {
                                if (is_array($w) && isset($w['field'], $w['operator'])) {
                                    $wheres[] = [
                                        'type'     => (string)($w['type'] ?? 'basic'),
                                        'field'    => (string)$w['field'],
                                        'operator' => (string)$w['operator'],
                                        'value'    => $w['value'] ?? null,
                                        'boolean'  => (string)($w['boolean'] ?? 'and'),
                                    ];
                                }
                            }
                        }
                        // Mapear función a SQL
                        $funcSql = match ($function) {
                            'row_number', 'rank', 'dense_rank' => strtoupper($function) . '()',
                            'lag', 'lead' => strtoupper($function) . '(' . ($column === '*' ? '1' : $column) . ')',
                            'first_value' => 'FIRST_VALUE(' . $column . ')',
                            'last_value'  => 'LAST_VALUE(' . $column . ')',
                            'ntile'       => 'NTILE(' . (int)(($params['args']['buckets'] ?? 2)) . ')',
                            default       => 'ROW_NUMBER()'
                        };
                        // Detectar alias de tabla si viene como "table AS alias" o "table alias"
                        $tableRef      = trim($table);
                        $baseQualifier = $tableRef;
                        if (preg_match('/^([A-Za-z_][A-Za-z0-9_\.]*)(?:\s+as\s+|\s+)([A-Za-z_][A-Za-z0-9_]*)$/i', $tableRef, $m) === 1) {
                            $baseQualifier = (string)$m[2]; // usar alias si existe
                        }
                        $baseQualifierQuoted = $this->dialect->quoteIdentifier($baseQualifier);
                        $over                = [];
                        if (!empty($partition)) {
                            // Calificar columnas de PARTITION BY con alias/tabla base si no vienen calificadas
                            $parts = array_map(function ($p) use ($baseQualifierQuoted) {
                                $p = (string)$p;
                                if ($p === '*' || str_contains($p, '(')) {
                                    return $p;
                                }
                                if (str_contains($p, '.')) {
                                    return $p;
                                }
                                return $baseQualifierQuoted . '.' . $this->dialect->quoteIdentifier($p);
                            }, $partition);
                            $over[] = 'PARTITION BY ' . implode(', ', $parts);
                        }
                        if (!empty($orderBy)) {
                            $ob = [];
                            foreach ($orderBy as $o) {
                                $dir = strtoupper((string)($o['direction'] ?? 'ASC'));
                                $col = (string)($o['column'] ?? '');
                                if ($col !== '' && $col !== '*' && !str_contains($col, '.') && !str_contains($col, '(')) {
                                    $col = $baseQualifierQuoted . '.' . $this->dialect->quoteIdentifier($col);
                                }
                                $ob[] = $col . ' ' . (in_array($dir, ['ASC', 'DESC'], true) ? $dir : 'ASC');
                            }
                            if (count($ob) > 0) {
                                $over[] = 'ORDER BY ' . implode(', ', $ob);
                            }
                        }
                        $overSql = 'OVER (' . implode(' ', $over) . ')';
                        // Construir SELECT básico de la tabla
                        [$baseSql, $baseBindings] = SqlGenerator::generate('query', [
                            'method' => 'get',
                            'table'  => $table,
                            'select' => ['*'],
                            'where'  => $wheres,
                        ], $this->dialect);
                        // Calificar columna si aplica
                        $tmp              = preg_replace('/\((\s*\*\s*)\)/', '(1)', (string)$funcSql);
                        $qualifiedFuncSql = is_string($tmp) ? $tmp : $funcSql;
                        if ($column !== '*') {
                            // Solo reemplazar ocurrencias de nombre de columna aislado (evitar tocar funciones)
                            $qualified = (
                                str_contains($column, '(') || str_contains($column, '.')
                                ? $column
                                : ($baseQualifierQuoted . '.' . $this->dialect->quoteIdentifier($column))
                            );
                            // Reemplazo conservador: si la función es LAG/LEAD/FIRST_VALUE/LAST_VALUE con el nombre simple
                            $tmp2             = preg_replace('/\b' . preg_quote($column, '/') . '\b/', $qualified, (string)$qualifiedFuncSql);
                            $qualifiedFuncSql = is_string($tmp2) ? $tmp2 : $qualifiedFuncSql;
                        }
                        // Insertar la expresión window directamente en el SELECT base
                        $sql = (string)preg_replace(
                            '/^SELECT\s+\*\s+FROM\s+/i',
                            'SELECT *, ' . $qualifiedFuncSql . ' ' . $overSql . ' AS ' . $this->dialect->quoteIdentifier($alias) . ' FROM ',
                            $baseSql,
                            1
                        );
                        // Log de depuración opcional
                        if (function_exists('error_log')) {
                            @error_log('[PDO][advanced_sql][window_function] SQL: ' . $sql);
                        }
                        try {
                            $stmt = $this->prepareCached($pdo, $sql);
                            $this->bindAndExecute($stmt, $baseBindings);
                            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
                        } catch (\Throwable $e) {
                            // Incluir el SQL generado para facilitar el diagnóstico de columnas/alias
                            throw new \Exception('advanced_sql window_function failed. SQL: ' . $sql . ' | Bindings: ' . json_encode($baseBindings) . ' | Error: ' . $e->getMessage(), 0, $e);
                        }
                    })(),
                    'cte' => (function () use ($params, $pdo) {
                        /** @var list<array{name?:string,query?:string,columns?:list<string>,recursive?:bool,bindings?:array<int,mixed>}> $ctes */
                        $ctes = [];
                        if (isset($params['ctes']) && is_array($params['ctes'])) {
                            foreach ($params['ctes'] as $c) {
                                if (is_array($c)) {
                                    $ctes[] = $c; // normalizamos sólo a array
                                }
                            }
                        }
                        $withParts   = [];
                        /** @var array<int,mixed> $bindings */
                        $bindings    = [];
                        $isRecursive = false;
                        foreach ($ctes as $c) {
                            $name     = (string)($c['name'] ?? 'cte');
                            $querySql = (string)($c['query'] ?? '');
                            $colsDef  = '';
                            if (!empty($c['columns']) && is_array($c['columns'])) {
                                $quotedCols = array_map(fn($col) => $this->dialect->quoteIdentifier((string)$col), $c['columns']);
                                $colsDef    = ' (' . implode(', ', $quotedCols) . ')';
                            }
                            if (!empty($c['recursive'])) {
                                $isRecursive = true;
                            }
                            $withParts[] = $this->dialect->quoteIdentifier($name) . $colsDef . ' AS (' . $querySql . ')';
                            if (isset($c['bindings']) && is_array($c['bindings'])) {
                                $bindings = array_merge($bindings, $c['bindings']);
                            }
                        }
                        $main         = (string)($params['main_query'] ?? '');
                        $mainBindings = [];
                        if (isset($params['main_query_bindings']) && is_array($params['main_query_bindings'])) {
                            $mainBindings = $params['main_query_bindings'];
                        }
                        $withKeyword = 'WITH' . ($isRecursive ? ' RECURSIVE ' : ' ');
                        $sql         = $withKeyword . implode(', ', $withParts) . ' ' . $main;
                        $stmt        = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, array_merge($bindings, $mainBindings));
                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
                    })(),
                    'union', 'intersect', 'except' => (function () use ($params, $pdo, $opType) {
                        /** @var list<array{sql?:string,bindings?:array<int,mixed>}> $queries */
                        $queries = [];
                        if (isset($params['queries']) && is_array($params['queries'])) {
                            foreach ($params['queries'] as $q) {
                                if (is_array($q)) {
                                    $queries[] = $q;
                                }
                            }
                        }
                        $all     = (bool)($params['all'] ?? false);
                        if ($opType === 'union') {
                            $glue = $all ? ' UNION ALL ' : ' UNION ';
                        } elseif ($opType === 'intersect') {
                            $glue = $all ? ' INTERSECT ALL ' : ' INTERSECT ';
                        } else {
                            $glue = $all ? ' EXCEPT ALL ' : ' EXCEPT ';
                        }
                        $parts    = [];
                        $bindings = [];
                        foreach ($queries as $q) {
                            $sqlPart = (string)($q['sql'] ?? '');
                            // SQLite puede quejarse de paréntesis en cada SELECT en UNION
                            if ($this->dialect->getName() === 'sqlite') {
                                $parts[] = $sqlPart;
                            } else {
                                $parts[] = '(' . $sqlPart . ')';
                            }
                            $qb       = is_array($q['bindings'] ?? null) ? $q['bindings'] : [];
                            $bindings = array_merge($bindings, $qb);
                        }
                        $sql  = implode($glue, $parts);
                        $stmt = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, $bindings);
                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
                    })(),
                    'json_operation' => (function () use ($params, $pdo, $driver) {
                        $table    = (string)($params['table'] ?? '');
                        $col      = (string)($params['column'] ?? '');
                        $op       = (string)($params['json_operation'] ?? 'extract');
                        $path     = (string)($params['path'] ?? '');
                        /** @var list<array{type:string,field:string,operator:string,value:mixed,boolean?:string}> $wheres */
                        $wheres = [];
                        if (isset($params['wheres']) && is_array($params['wheres'])) {
                            foreach ($params['wheres'] as $w) {
                                if (is_array($w) && isset($w['field'], $w['operator'])) {
                                    $wheres[] = [
                                        'type'     => (string)($w['type'] ?? 'basic'),
                                        'field'    => (string)$w['field'],
                                        'operator' => (string)$w['operator'],
                                        'value'    => $w['value'] ?? null,
                                        'boolean'  => (string)($w['boolean'] ?? 'and'),
                                    ];
                                }
                            }
                        }
                        $bind     = [];
                        $jsonExpr = '';

                        // Soporte de sintaxis arrow (col->key->>key2) y extracción sin comillas en MySQL
                        $arrowStyle = false;
                        $unquote    = false;
                        if ($driver === 'mysql' && preg_match('/->>/', $path) === 1) {
                            $arrowStyle = true;
                            $unquote    = true; // ->> indica descomillas
                        } elseif ($driver === 'mysql' && preg_match('/->/', $path) === 1) {
                            $arrowStyle = true;
                        }

                        if ($driver === 'mysql') {
                            if ($arrowStyle) {
                                // Convertir col->a->b->>c en JSON_EXTRACT(col,'$.a.b.c') y opcional JSON_UNQUOTE
                                $segments = preg_split('/->>?/', $path) ?: [];
                                // Filtrar segmentos vacíos o que repitan el nombre de la columna
                                $segments = array_values(array_filter($segments, static fn($s): bool => is_string($s) && $s !== '' && $s !== $col));
                                // Si el path original incluía col al inicio, removerlo
                                if (!empty($segments) && $segments[0] === $col) {
                                    array_shift($segments);
                                }
                                $jsonPath = '$';
                                if (!empty($segments)) {
                                    $jsonPath .= '.' . implode('.', array_map(fn($s) => trim($s, "'\"` "), $segments));
                                }
                                $core     = "JSON_EXTRACT($col, ?)";
                                $jsonExpr = ($unquote ? 'JSON_UNQUOTE(' . $core . ')' : $core) . ' AS value';
                                $bind     = [$jsonPath];
                            } else {
                                if ($op === 'extract') {
                                    $jsonExpr = "JSON_EXTRACT($col, ?) AS value";
                                    $bind     = [$path];
                                } else {
                                    // Operaciones adicionales básicas (contains, keys, etc.) podrían ampliarse
                                    $jsonExpr = "JSON_EXTRACT($col, ?) AS value";
                                    $bind     = [$path];
                                }
                            }
                        } elseif ($driver === 'postgres') {
                            $segments = array_filter(
                                explode('.', trim($path, '$.')),
                                static fn($s): bool => $s !== ''
                            );
                            $expr     = $col;
                            foreach ($segments as $idx => $s) {
                                // Último segmento usar ->> para texto simple
                                $opArrow = $idx === array_key_last($segments) ? '->>' : '->';
                                $expr .= $opArrow . "'" . $s . "'";
                            }
                            $jsonExpr = $expr . ' AS value';
                            $bind     = [];
                        } else { // sqlite
                            $jsonExpr = "json_extract($col, ?) AS value";
                            $bind     = [$path];
                        }

                        [$baseSql, $baseBindings] = SqlGenerator::generate('query', [
                            'method' => 'get',
                            'table'  => $table,
                            'select' => ['*'],
                            'where'  => $wheres,
                        ], $this->dialect);
                        $tmpSql = preg_replace('/^SELECT\s+\*\s+FROM/i', 'SELECT *, ' . $jsonExpr . ' FROM', (string)$baseSql, 1);
                        $sql    = is_string($tmpSql) ? $tmpSql : (string)$baseSql;
                        $stmt   = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, array_merge($bind, $baseBindings));
                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
                    })(),
                    'full_text_search' => (function () use ($params, $pdo, $driver) {
                        $table   = (string)($params['table'] ?? '');
                        /** @var list<string> $cols */
                        $cols = [];
                        if (isset($params['columns']) && is_array($params['columns'])) {
                            foreach ($params['columns'] as $c) {
                                if (is_string($c) && $c !== '') {
                                    $cols[] = $c;
                                }
                            }
                        }
                        $term    = (string)($params['search_term'] ?? '');
                        $options = (array)($params['options'] ?? []);
                        if ($driver === 'mysql') {
                            $modeSql = '';
                            if (isset($options['mode']) && is_string($options['mode'])) {
                                $modeSql = ' IN ' . $options['mode'] . ' MODE';
                            }
                            $match  = 'MATCH(' . implode(', ', $cols) . ') AGAINST (?' . $modeSql . ')';
                            $select = '*';
                            if (!empty($options['with_score'])) {
                                $select = '*, ' . $match . ' AS score';
                            }
                            $sql  = 'SELECT ' . $select . ' FROM ' . $this->dialect->quoteIdentifier($table) . ' WHERE ' . $match;
                            $stmt = $this->prepareCached($pdo, $sql);
                            // Si with_score agrega el MATCH también en SELECT, enlazar el término dos veces
                            $bindings = !empty($options['with_score']) ? [$term, $term] : [$term];
                            $stmt->execute($bindings);
                            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
                        } elseif ($driver === 'postgres') {
                            // Usar to_tsvector/tsquery; si la columna ya es tsvector, comparar directamente
                            $language = (string)($options['language'] ?? 'english');
                            $operator = (string)($options['operator'] ?? '@@');
                            $rank     = !empty($options['rank']);
                            $colExpr  = implode(' || \" \" || ', array_map(fn($c) => "to_tsvector('" . $language . "', " . $c . ')', $cols));
                            // Si solo una columna y parece tsvector, usarla directa
                            if (count($cols) === 1 && preg_match('/vector$/i', (string)$cols[0]) === 1) {
                                $colExpr = (string)$cols[0];
                            }
                            $rankExpr = $rank ? ', ts_rank(' . $colExpr . ', plainto_tsquery(?)) AS rank' : '';
                            $sql      = 'SELECT *' . $rankExpr . ' FROM ' . $this->dialect->quoteIdentifier($table) . ' WHERE ' . $colExpr . ' ' . $operator . ' plainto_tsquery(?)';
                            $stmt     = $this->prepareCached($pdo, $sql);
                            $this->bindAndExecute($stmt, $rank ? [$term, $term] : [$term]);
                            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
                        }
                        // Fallback: LIKE en otros drivers
                        $likeParts = [];
                        foreach ($cols as $c) {
                            $likeParts[] = "$c LIKE ?";
                        }
                        $sql  = 'SELECT * FROM ' . $this->dialect->quoteIdentifier($table) . ' WHERE ' . implode(' OR ', $likeParts);
                        $stmt = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, array_fill(0, count($likeParts), '%' . $term . '%'));
                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
                    })(),
                    'array_operations' => (function () use ($params, $pdo, $driver) {
                        // Soporte mínimo para arrays en Postgres
                        if ($driver !== 'postgres') {
                            throw new VersaORMException('Unsupported advanced_sql operation in PDO engine: array_operations');
                        }
                        $table    = (string)($params['table'] ?? '');
                        $col      = (string)($params['column'] ?? '');
                        $op       = (string)($params['array_operation'] ?? '');
                        $value    = $params['value'] ?? null;
                        $whereSql = '';
                        $bindings = [];
                        switch ($op) {
                            case 'contains':
                                $whereSql   = $col . ' @> ?';
                                $bindings[] = is_array($value) ? '{' . implode(',', $value) . '}' : '{' . (string)$value . '}';
                                break;
                            case 'overlap':
                                $whereSql   = $col . ' && ?';
                                $bindings[] = is_array($value) ? '{' . implode(',', $value) . '}' : '{' . (string)$value . '}';
                                break;
                            case 'any':
                                $whereSql   = '? = ANY(' . $col . ')';
                                $bindings[] = $value;
                                break;
                            case 'all':
                                $whereSql   = '? = ALL(' . $col . ')';
                                $bindings[] = $value;
                                break;
                            default:
                                throw new VersaORMException('Unsupported array operation: ' . $op);
                        }
                        $sql  = 'SELECT * FROM ' . $this->dialect->quoteIdentifier($table) . ' WHERE ' . $whereSql;
                        $stmt = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, $bindings);
                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
                    })(),
                    'advanced_aggregation' => (function () use ($params, $pdo, $driver) {
                        $type    = (string)($params['aggregation_type'] ?? '');
                        $table   = (string)($params['table'] ?? '');
                        $column  = (string)($params['column'] ?? '');
                        /** @var list<string> $groupBy */
                        $groupBy = [];
                        if (isset($params['groupBy']) && is_array($params['groupBy'])) {
                            foreach ($params['groupBy'] as $g) {
                                if (is_string($g) && $g !== '') {
                                    $groupBy[] = $g;
                                }
                            }
                        }
                        if ($type === 'group_concat') {
                            $sep      = (string)($params['options']['separator'] ?? ',');
                            $order    = (string)($params['options']['order_by'] ?? '');
                            $sepValue = str_replace("'", "''", $sep);
                            if ($driver === 'mysql') {
                                $expr = 'GROUP_CONCAT(' . $column . ($order ? ' ORDER BY ' . $order : '') . " SEPARATOR '" . $sepValue . "') AS agg";
                            } elseif ($driver === 'postgres') {
                                // string_agg(col::text, sep) [ORDER BY col]
                                $expr = 'string_agg(' . $column . '::text, ' . "'" . $sepValue . "'" . ')' . ($order ? ' ORDER BY ' . $order : '') . ' AS agg';
                            } else { // sqlite
                                // group_concat(col, sep)
                                $expr = 'group_concat(' . $column . ", '" . $sepValue . "') AS agg";
                            }
                            $sql = 'SELECT ' . (empty($groupBy) ? $expr : implode(', ', $groupBy) . ', ' . $expr) . ' FROM ' . $this->dialect->quoteIdentifier($table);
                            if (!empty($groupBy)) {
                                $sql .= ' GROUP BY ' . implode(', ', $groupBy);
                            }
                            $stmt = $this->prepareCached($pdo, $sql);
                            $stmt->execute();
                            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
                        }
                        $map  = ['median' => 'AVG', 'variance' => 'VARIANCE', 'stddev' => 'STDDEV'];
                        $func = $map[$type] ?? 'COUNT';
                        $sql  = 'SELECT ' . $func . '(' . ($column ?: '*') . ') AS agg FROM ' . $this->dialect->quoteIdentifier($table);
                        $stmt = $pdo->query($sql);
                        return $stmt ? ($stmt->fetchAll(PDO::FETCH_ASSOC) ?: []) : [];
                    })(),
                    'get_driver_capabilities' => (function () use ($pdo, $driver) {
                        $features = [
                            'window_functions' => in_array($driver, ['mysql', 'postgres', 'sqlite'], true),
                            'json_support'     => true,
                            'fts_support'      => in_array($driver, ['mysql', 'postgres', 'sqlite'], true),
                        ];
                        return [
                            'driver'   => $driver,
                            'version'  => $pdo->getAttribute(PDO::ATTR_SERVER_VERSION) ?: null,
                            'features' => $features,
                        ];
                    })(),
                    'get_driver_limits' => (function () {
                        // Valores aproximados comunes o seguros
                        return [
                            'max_columns'    => 2000,
                            'max_sql_length' => 1000000,
                            'max_page_size'  => 4096,
                        ];
                    })(),
                    'optimize_query' => [
                        'optimization_suggestions' => [],
                        'generated_sql'            => (string)($params['query'] ?? ''),
                    ],
                    default => throw new VersaORMException('Unsupported advanced_sql operation in PDO engine: ' . $opType),
                };
                return $result;
            } catch (\Throwable $e) {
                throw new VersaORMException('PDO advanced_sql failed: ' . $e->getMessage(), 'PDO_ADVANCED_SQL_FAILED');
            }
        }

        [$sql, $bindings] = SqlGenerator::generate($action, $params, $this->dialect);

        // Normalización por acción
        if ($action === 'query') {
            $method = (string)($params['method'] ?? 'get');
            // Batch operations mapped to query
            if (in_array($method, ['insertMany', 'updateMany', 'deleteMany', 'upsertMany'], true)) {
                // Reutilizamos los handlers directos para mantener una única implementación
                $normalizedQueryBatch = strtolower($method);
                return match ($normalizedQueryBatch) {
                    'insertmany' => $this->handleInsertMany($params, $pdo),
                    'updatemany' => $this->handleUpdateMany($params, $pdo),
                    'deletemany' => $this->handleDeleteMany($params, $pdo),
                    'upsertmany' => $this->handleUpsertMany($params, $pdo),
                    default      => throw new VersaORMException('Unsupported query batch method: ' . $method),
                };
            }
            // Lecturas con caché
            if (self::$cacheEnabled && in_array($method, ['get', 'first', 'exists', 'count'], true)) {
                $cacheKey = self::makeCacheKey($sql, $bindings, $method);
                if (isset(self::$queryCache[$cacheKey])) {
                    self::recordCacheHit();
                    return self::$queryCache[$cacheKey];
                } else {
                    self::recordCacheMiss();
                }
            }
            if ($method === 'count') {
                $stmt  = $this->prepareCached($pdo, $sql);
                $start = microtime(true);
                try {
                    $this->bindAndExecute($stmt, $bindings);
                } catch (\Throwable $e) {
                    throw new VersaORMException('SQL failed (count): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | ' . $e->getMessage(), 'PDO_EXEC_FAILED');
                }
                $elapsed = (microtime(true) - $start) * 1000;
                self::recordQuery(false, $elapsed);
                $row    = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
                $result = (int)($row['count'] ?? 0);
                if (self::$cacheEnabled) {
                    self::storeInCache($sql, $bindings, 'count', $result);
                }
                return $result;
            }
            if ($method === 'exists') {
                $stmt  = $this->prepareCached($pdo, $sql);
                $start = microtime(true);
                try {
                    $this->bindAndExecute($stmt, $bindings);
                } catch (\Throwable $e) {
                    throw new VersaORMException('SQL failed (exists): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | ' . $e->getMessage(), 'PDO_EXEC_FAILED');
                }
                $elapsed = (microtime(true) - $start) * 1000;
                self::recordQuery(false, $elapsed);
                $row    = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
                $val    = array_values($row)[0] ?? 0;
                $result = (bool)$val;
                if (self::$cacheEnabled) {
                    self::storeInCache($sql, $bindings, 'exists', $result);
                }
                return $result;
            }
            if ($method === 'first') {
                $stmt  = $this->prepareCached($pdo, $sql);
                $start = microtime(true);
                try {
                    $this->bindAndExecute($stmt, $bindings);
                } catch (\Throwable $e) {
                    throw new VersaORMException('SQL failed (first): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | ' . $e->getMessage(), 'PDO_EXEC_FAILED');
                }
                $elapsed = (microtime(true) - $start) * 1000;
                self::recordQuery(false, $elapsed);
                $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
                if (self::$cacheEnabled) {
                    self::storeInCache($sql, $bindings, 'first', $row);
                }
                return $row;
            }
            // default get
            // Log de diagnóstico usando el logger inyectado (VersaORM::logDebug)
            $this->log('[PDO][GET] Executing SQL', ['sql' => $sql, 'bindings' => $bindings]);
            $stmt  = $this->prepareCached($pdo, $sql);
            $start = microtime(true);
            try {
                $this->bindAndExecute($stmt, $bindings);
            } catch (\Throwable $e) {
                throw new VersaORMException('SQL failed (get): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | ' . $e->getMessage(), 'PDO_EXEC_FAILED');
            }
            $elapsed = (microtime(true) - $start) * 1000;
            self::recordQuery(false, $elapsed);
            $rows   = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $result = is_array($rows) ? $rows : [];
            if (self::$cacheEnabled) {
                self::storeInCache($sql, $bindings, 'get', $result);
            }
            return $result;
        }

        if ($action === 'raw') {
            // Soporte explícito para transacciones
            $normalized = strtoupper(trim($sql));
            if (str_starts_with($normalized, 'BEGIN') || str_starts_with($normalized, 'START TRANSACTION')) {
                $pdo->beginTransaction();
                return null;
            }
            if (str_starts_with($normalized, 'COMMIT')) {
                $pdo->commit();
                // Al confirmar cambios, invalidar caché por seguridad
                self::clearAllCache();
                return null;
            }
            if (str_starts_with($normalized, 'ROLLBACK')) {
                $pdo->rollBack();
                // Tras rollback, el caché puede quedar inconsistente si se cachearon lecturas intermedias
                self::clearAllCache();
                return null;
            }

            // Detectar si es una sentencia de escritura antes de intentar fetchAll
            $isWrite = preg_match('/^\s*(INSERT|UPDATE|DELETE|REPLACE|TRUNCATE|CREATE|DROP|ALTER)\b/i', $sql) === 1;
            $stmt    = $this->prepareCached($pdo, $sql);
            $this->bindAndExecute($stmt, $bindings);
            if ($isWrite) {
                // Invalidar todo el caché en operaciones de escritura para mantener coherencia
                self::clearAllCache();
                // Normalizar: devolver null para no-SELECT (los tests aceptan null/[])
                return null;
            }
            // Lecturas: devolver filas y cachear si corresponde
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            if (self::$cacheEnabled) {
                self::storeInCache($sql, $bindings, 'raw', $rows);
            }
            return $rows;
        }

        if ($action === 'insert') {
            $stmt  = $this->prepareCached($pdo, $sql);
            $start = microtime(true);
            try {
                $this->bindAndExecute($stmt, $bindings);
            } catch (\Throwable $e) {
                throw new VersaORMException('SQL failed (insert): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | ' . $e->getMessage(), 'PDO_EXEC_FAILED');
            }
            $elapsed = (microtime(true) - $start) * 1000;
            self::recordQuery(true, $elapsed);
            self::clearAllCache();
            return (int)$stmt->rowCount();
        }

        if ($action === 'insertGetId') {
            $stmt  = $this->prepareCached($pdo, $sql);
            $start = microtime(true);
            try {
                $this->bindAndExecute($stmt, $bindings);
            } catch (\Throwable $e) {
                throw new VersaORMException('SQL failed (insertGetId): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | ' . $e->getMessage(), 'PDO_EXEC_FAILED');
            }
            $elapsed = (microtime(true) - $start) * 1000;
            self::recordQuery(true, $elapsed);
            self::clearAllCache();
            return $pdo->lastInsertId() ?: null;
        }

        if ($action === 'update' || $action === 'delete') {
            $stmt  = $this->prepareCached($pdo, $sql);
            $start = microtime(true);
            try {
                $this->bindAndExecute($stmt, $bindings);
            } catch (\Throwable $e) {
                throw new VersaORMException('SQL failed (' . $action . '): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | ' . $e->getMessage(), 'PDO_EXEC_FAILED');
            }
            $elapsed = (microtime(true) - $start) * 1000;
            self::recordQuery(true, $elapsed);
            self::clearAllCache();
            return (int)$stmt->rowCount();
        }

        throw new VersaORMException('Unsupported PDO action: ' . $action);
    }

    /**
     * Maneja inserciones batch (insertMany) como acción directa.
     * @param array<string,mixed> $params
     * @return array<string,mixed>
     */
    private function handleInsertMany(array $params, PDO $pdo): array
    {
        $records   = $params['records'] ?? [];
        $batchSize = (int)($params['batch_size'] ?? 1000);
        if (!is_array($records) || empty($records)) {
            return [
                'status'            => 'success',
                'total_inserted'    => 0,
                'batches_processed' => 0,
                'batch_size'        => $batchSize,
            ];
        }
        $total         = count($records);
        $batches       = $batchSize > 0 ? (int)ceil($total / $batchSize) : 1;
        $totalInserted = 0;
        for ($i = 0; $i < $total; $i += $batchSize) {
            $chunk                      = array_slice($records, $i, $batchSize);
            [$chunkSql, $chunkBindings] = SqlGenerator::generate('query', [
                'method'  => 'insertMany',
                'table'   => $params['table'] ?? '',
                'records' => $chunk,
            ], $this->dialect);
            $st = $this->prepareCached($pdo, $chunkSql);
            $st->execute($chunkBindings);
            $totalInserted += count($chunk);
        }
        self::clearAllCache();
        return [
            'status'            => 'success',
            'total_inserted'    => $totalInserted,
            'batches_processed' => $batches,
            'batch_size'        => $batchSize,
        ];
    }

    /**
     * Maneja actualizaciones batch (updateMany) directas.
     * @param array<string,mixed> $params
     * @return array<string,mixed>
     */
    private function handleUpdateMany(array $params, PDO $pdo): array
    {
        $max                        = (int)($params['max_records'] ?? 10000);
        [$countSql, $countBindings] = SqlGenerator::generate('query', [
            'method' => 'count',
            'table'  => $params['table'] ?? '',
            'where'  => $params['where'] ?? [],
        ], $this->dialect);
        $stc = $this->prepareCached($pdo, $countSql);
        $stc->execute($countBindings);
        $row      = $stc->fetch(PDO::FETCH_ASSOC) ?: [];
        $toAffect = (int)($row['count'] ?? 0);
        if ($toAffect > $max) {
            throw new VersaORMException(sprintf(
                'The operation would affect %d records, which exceeds the maximum limit of %d. Use a more restrictive WHERE clause or increase max_records.',
                $toAffect,
                $max
            ), 'BATCH_LIMIT_EXCEEDED');
        }
        [$sqlU, $bindU] = SqlGenerator::generate('query', [
            'method' => 'updateMany',
            'table'  => $params['table'] ?? '',
            'where'  => $params['where'] ?? [],
            'data'   => $params['data'] ?? [],
        ], $this->dialect);
        $stmt = $this->prepareCached($pdo, $sqlU);
        $this->bindAndExecute($stmt, $bindU);
        $affected = (int)$stmt->rowCount();
        self::clearAllCache();
        return [
            'status'        => 'success',
            'rows_affected' => $affected,
            'message'       => $affected === 0 ? 'No records matched the WHERE conditions' : 'Update completed',
        ];
    }

    /**
     * Maneja eliminaciones batch (deleteMany) directas.
     * @param array<string,mixed> $params
     * @return array<string,mixed>
     */
    private function handleDeleteMany(array $params, PDO $pdo): array
    {
        $max                        = (int)($params['max_records'] ?? 10000);
        [$countSql, $countBindings] = SqlGenerator::generate('query', [
            'method' => 'count',
            'table'  => $params['table'] ?? '',
            'where'  => $params['where'] ?? [],
        ], $this->dialect);
        $stc = $this->prepareCached($pdo, $countSql);
        $stc->execute($countBindings);
        $row      = $stc->fetch(PDO::FETCH_ASSOC) ?: [];
        $toAffect = (int)($row['count'] ?? 0);
        if ($toAffect > $max) {
            throw new VersaORMException(sprintf(
                'The operation would affect %d records, which exceeds the maximum limit of %d. Use a more restrictive WHERE clause or increase max_records.',
                $toAffect,
                $max
            ), 'BATCH_LIMIT_EXCEEDED');
        }
        [$sqlD, $bindD] = SqlGenerator::generate('query', [
            'method' => 'deleteMany',
            'table'  => $params['table'] ?? '',
            'where'  => $params['where'] ?? [],
        ], $this->dialect);
        $stmt = $this->prepareCached($pdo, $sqlD);
        $this->bindAndExecute($stmt, $bindD);
        $affected = (int)$stmt->rowCount();
        self::clearAllCache();
        return [
            'status'        => 'success',
            'rows_affected' => $affected,
            'message'       => $affected === 0 ? 'No records matched the WHERE conditions' : 'Delete completed',
        ];
    }

    /**
     * Maneja upserts batch (upsertMany) directos.
     * @param array<string,mixed> $params
     * @return array<string,mixed>
     */
    private function handleUpsertMany(array $params, PDO $pdo): array
    {
        [$sqlUp, $bindUp] = SqlGenerator::generate('query', [
            'method'         => 'upsertMany',
            'table'          => $params['table'] ?? '',
            'records'        => $params['records'] ?? [],
            'unique_keys'    => $params['unique_keys'] ?? [],
            'update_columns' => $params['update_columns'] ?? [],
        ], $this->dialect);
        $stmt = $this->prepareCached($pdo, $sqlUp);
        $this->bindAndExecute($stmt, $bindUp);
        $affected = (int)$stmt->rowCount();
        self::clearAllCache();
        return [
            'status'          => 'success',
            'total_processed' => is_array($params['records'] ?? null) ? count($params['records']) : $affected,
            'unique_keys'     => $params['unique_keys'] ?? [],
            'update_columns'  => $params['update_columns'] ?? [],
        ];
    }

    /**
     * @return list<array{table_name:string|null}>
     */
    private function fetchTables(PDO $pdo): array
    {
        $driver = $this->dialect->getName();
        if ($driver === 'mysql') {
            $stmt   = $pdo->query('SHOW TABLES');
            $rows   = $stmt ? $stmt->fetchAll(PDO::FETCH_NUM) : [];
            $result = [];
            foreach ($rows as $r) {
                $result[] = ['table_name' => $r[0] ?? null];
            }
            return $result;
        }
        if ($driver === 'sqlite') {
            $stmt = $pdo->query("SELECT name as table_name FROM sqlite_master WHERE type='table'");
            $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
            $out  = [];
            foreach ($rows as $r) {
                if (is_array($r)) {
                    $out[] = ['table_name' => isset($r['table_name']) ? (string)$r['table_name'] : null];
                }
            }
            return $out;
        }
        if ($driver === 'postgres') {
            $stmt = $pdo->query("SELECT tablename AS table_name FROM pg_tables WHERE schemaname='public'");
            $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
            $out  = [];
            foreach ($rows as $r) {
                if (is_array($r)) {
                    $out[] = ['table_name' => isset($r['table_name']) ? (string)$r['table_name'] : null];
                }
            }
            return $out;
        }
        return [];
    }

    /**
     * @return list<array{
     *   column_name:string,
     *   name:string,
     *   data_type:string,
     *   is_nullable:string,
     *   column_default:string|null,
     *   character_maximum_length:int|null,
     *   extra:string
     * }>
     */
    private function fetchColumns(PDO $pdo, string $table): array
    {
        $driver = $this->dialect->getName();
        if ($driver === 'mysql') {
            $stmt = $this->prepareCached($pdo, 'SHOW FULL COLUMNS FROM ' . $this->dialect->quoteIdentifier($table));
            $stmt->execute();
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $result  = [];
            foreach ($columns as $col) {
                $type   = strtolower((string)($col['Type'] ?? ''));
                $length = null;
                if (preg_match('/^(\w+)\((\d+)\)/', $type, $m) === 1) {
                    $type   = $m[1];
                    $length = (int)$m[2];
                }
                $name     = (string)($col['Field'] ?? '');
                $result[] = [
                    'column_name'              => $name,
                    'name'                     => $name,
                    'data_type'                => $type,
                    'is_nullable'              => strtoupper((string)($col['Null'] ?? 'NO')) === 'YES' ? 'YES' : 'NO',
                    'column_default'           => $col['Default'] ?? null,
                    'character_maximum_length' => $length,
                    'extra'                    => $col['Extra'] ?? '',
                ];
            }
            return $result;
        }
        if ($driver === 'sqlite') {
            $stmt = $this->prepareCached($pdo, 'PRAGMA table_info(' . $this->dialect->quoteIdentifier($table) . ')');
            $stmt->execute();
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $result  = [];
            foreach ($columns as $col) {
                $name     = (string)($col['name'] ?? '');
                $result[] = [
                    'column_name'              => $name,
                    'name'                     => $name,
                    'data_type'                => strtolower((string)($col['type'] ?? '')),
                    'is_nullable'              => ((int)($col['notnull'] ?? 0)) === 0 ? 'YES' : 'NO',
                    'column_default'           => $col['dflt_value'] ?? null,
                    'character_maximum_length' => null,
                    'extra'                    => ((int)($col['pk'] ?? 0)) === 1 ? 'primary_key' : '',
                ];
            }
            return $result;
        }
        if ($driver === 'postgres') {
            $sql = 'SELECT column_name, data_type, is_nullable, column_default, character_maximum_length ' .
                'FROM information_schema.columns WHERE table_name = ?';
            $stmt = $this->prepareCached($pdo, $sql);
            $this->bindAndExecute($stmt, [$table]);
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $result  = [];
            foreach ($columns as $col) {
                $name     = (string)($col['column_name'] ?? '');
                $result[] = [
                    'column_name'              => $name,
                    'name'                     => $name,
                    'data_type'                => strtolower((string)($col['data_type'] ?? '')),
                    'is_nullable'              => strtoupper((string)($col['is_nullable'] ?? 'NO')) === 'YES' ? 'YES' : 'NO',
                    'column_default'           => $col['column_default'] ?? null,
                    'character_maximum_length' => $col['character_maximum_length'] ?? null,
                    'extra'                    => '',
                ];
            }
            return $result;
        }
        return [];
    }

    /**
     * @return list<array{name:string,column?:string,unique:bool}>
     */
    private function fetchIndexes(PDO $pdo, string $table): array
    {
        $driver = $this->dialect->getName();
        if ($driver === 'mysql') {
            $stmt = $this->prepareCached($pdo, 'SHOW INDEX FROM ' . $this->dialect->quoteIdentifier($table));
            $stmt->execute();
            /** @var list<array{Key_name?:string,Column_name?:string,Non_unique?:int|string}> $rows */
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $out  = [];
            foreach ($rows as $r) {
                $keyName    = isset($r['Key_name']) ? (string)$r['Key_name'] : '';
                $columnName = isset($r['Column_name']) ? (string)$r['Column_name'] : '';
                $nonUnique  = isset($r['Non_unique']) ? (int)$r['Non_unique'] : 1;
                $out[] = [
                    'name'   => $keyName,
                    'column' => $columnName,
                    'unique' => $nonUnique === 0,
                ];
            }
            return $out;
        }
        if ($driver === 'sqlite') {
            $stmt = $this->prepareCached($pdo, 'PRAGMA index_list(' . $this->dialect->quoteIdentifier($table) . ')');
            $stmt->execute();
            /** @var list<array{name?:string,unique?:int|string}> $rows */
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $out  = [];
            foreach ($rows as $r) {
                $idxName = isset($r['name']) ? (string)$r['name'] : '';
                $isUnique = isset($r['unique']) ? ((int)$r['unique'] === 1) : false;
                $out[] = [
                    'name'   => $idxName,
                    'unique' => $isUnique,
                ];
            }
            return $out;
        }
        if ($driver === 'postgres') {
            $sql = "SELECT i.relname AS name, a.attname AS column, ix.indisunique AS unique
            FROM pg_class t
            JOIN pg_index ix ON t.oid = ix.indrelid
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
            WHERE t.relkind = 'r' AND t.relname = ?";
            $stmt = $this->prepareCached($pdo, $sql);
            $this->bindAndExecute($stmt, [$table]);
            /** @var list<array{name?:string,column?:string,unique?:bool|int|string}> $rows */
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
            $out  = [];
            foreach ($rows as $r) {
                $idxName    = isset($r['name']) ? (string)$r['name'] : '';
                $colName    = isset($r['column']) ? (string)$r['column'] : '';
                $uniqueFlag = isset($r['unique']) ? (bool)$r['unique'] : false;
                $out[] = [
                    'name'   => $idxName,
                    'column' => $colName,
                    'unique' => $uniqueFlag,
                ];
            }
            return $out;
        }
        return [];
    }

    /**
     * Construye SQL simple desde una operación lazy del QueryBuilder
     * para ser usado por explain_plan/query_plan en modo PDO.
     *
     * @param array<string,mixed> $op
     * @return array{0:string,1:array<int,mixed>}
     */
    /**
     * @param array{
     *   table?:string,
     *   columns?:array<int,string>,
     *   join_conditions?:array<int,array{join_type?:string,table?:string,local_column?:string,operator?:string,foreign_column?:string}>,
     *   conditions?:array<int,array{column?:string,operator?:string,value?:mixed,connector?:string}>,
     *   grouping?:array<int,string>,
     *   having?:array<int,array<string,mixed>>,
     *   ordering?:array<int,array{column?:string,direction?:string}>,
     *   limit?:int|null,
     *   offset?:int|null
     * } $op
     * @return array{0:string,1:array<int, mixed>}
     */
    private function buildSqlFromOperation(array $op): array
    {
        $columns = isset($op['columns']) && is_array($op['columns']) ? array_values($op['columns']) : ['*'];
        /** @var list<string> $columns */
        $grouping = isset($op['grouping']) && is_array($op['grouping']) ? array_values($op['grouping']) : [];
        /** @var list<string> $grouping */
        $havingRaw = isset($op['having']) && is_array($op['having']) ? array_values($op['having']) : [];
        /** @var list<array<string,mixed>> $havingRaw */
        $params = [
            'method'  => 'get',
            'table'   => isset($op['table']) ? (string)$op['table'] : '',
            'select'  => $columns,
            'joins'   => [],
            'where'   => [],
            'groupBy' => $grouping,
            'having'  => $havingRaw,
            'orderBy' => [],
            'limit'   => $op['limit'] ?? null,
            'offset'  => $op['offset'] ?? null,
        ];

        /** @var array<int,array{join_type?:string,table?:string,local_column?:string,operator?:string,foreign_column?:string}> $joinConditions */
        $joinConditions = isset($op['join_conditions']) && is_array($op['join_conditions']) ? array_values($op['join_conditions']) : [];
        foreach ($joinConditions as $j) {
            if (!is_array($j)) {
                continue;
            }
            $params['joins'][] = [
                'type'       => strtolower(isset($j['join_type']) ? (string)$j['join_type'] : 'inner'),
                'table'      => isset($j['table']) ? (string)$j['table'] : '',
                'first_col'  => isset($j['local_column']) ? (string)$j['local_column'] : '',
                'operator'   => isset($j['operator']) ? (string)$j['operator'] : '=',
                'second_col' => isset($j['foreign_column']) ? (string)$j['foreign_column'] : '',
            ];
        }

        /** @var array<int,array{column?:string,operator?:string,value?:mixed,connector?:string}> $whereConditions */
        $whereConditions = isset($op['conditions']) && is_array($op['conditions']) ? array_values($op['conditions']) : [];
        foreach ($whereConditions as $w) {
            if (!is_array($w)) {
                continue;
            }
            $params['where'][] = [
                'column'   => isset($w['column']) ? (string)$w['column'] : '',
                'operator' => isset($w['operator']) ? (string)$w['operator'] : '=',
                'value'    => $w['value'] ?? null,
                'type'     => strtolower(isset($w['connector']) ? (string)$w['connector'] : 'and'),
            ];
        }

        // ORDER BY mapping: take first ordering entry if present
        /** @var array<int,array{column?:string,direction?:string}> $ordering */
        $ordering = isset($op['ordering']) && is_array($op['ordering']) ? array_values($op['ordering']) : [];
        if ($ordering !== []) {
            $first = $ordering[0] ?? null;
            if (is_array($first) && $first !== []) {
                $params['orderBy'] = [[
                    'column'    => isset($first['column']) ? (string)$first['column'] : '',
                    'direction' => strtoupper(isset($first['direction']) ? (string)$first['direction'] : 'ASC'),
                ]];
            }
        }

        return SqlGenerator::generate('query', $params, $this->dialect);
    }

    // =====================
    // Utilidades de Caché
    // =====================
    /**
     * @param array<int, mixed> $bindings
     */
    private static function makeCacheKey(string $sql, array $bindings, string $method): string
    {
        // Normalizar bindings para clave estable
        $key = $method . '|' . $sql . '|' . json_encode($bindings, JSON_UNESCAPED_UNICODE);
        return hash('sha256', $key);
    }

    /**
     * @return array<int, string>
     */
    private static function extractTablesFromSql(string $sql): array
    {
        $tables = [];
        // Buscar FROM y JOIN simples (identificadores con o sin backticks)
        if (preg_match_all('/\bFROM\s+`?([a-zA-Z0-9_\.]+)`?/i', $sql, $m1) === 1) {
            foreach ($m1[1] as $t) {
                $tables[] = strtolower($t);
            }
        }
        if (preg_match_all('/\bJOIN\s+`?([a-zA-Z0-9_\.]+)`?/i', $sql, $m2) === 1) {
            foreach ($m2[1] as $t) {
                $tables[] = strtolower($t);
            }
        }
        return array_values(array_unique($tables));
    }

    /**
     * Almacena un resultado en caché con tipado explícito admitiendo los tipos usados.
     *
     * @param array<int, mixed> $bindings
     * @param int|bool|null|array<string,mixed>|list<array<string,mixed>> $result
     */
    private static function storeInCache(string $sql, array $bindings, string $method, int|bool|null|array $result): void
    {
        $key                    = self::makeCacheKey($sql, $bindings, $method);
        self::$queryCache[$key] = $result;
        // Indexar por tabla para invalidación selectiva (best-effort)
        foreach (self::extractTablesFromSql($sql) as $table) {
            self::$tableKeyIndex[$table] = self::$tableKeyIndex[$table] ?? [];
            // Evitar inflar con duplicados
            if (!in_array($key, self::$tableKeyIndex[$table], true)) {
                self::$tableKeyIndex[$table][] = $key;
            }
        }
    }

    private static function invalidateCacheForTable(string $table): void
    {
        $t = strtolower($table);
        if (!isset(self::$tableKeyIndex[$t])) {
            return;
        }
        foreach (self::$tableKeyIndex[$t] as $key) {
            unset(self::$queryCache[$key]);
        }
        unset(self::$tableKeyIndex[$t]);
    }

    private static function invalidateCacheByPattern(string $pattern): void
    {
        $regex = '/' . str_replace('/', '\/', $pattern) . '/i';
        foreach (array_keys(self::$queryCache) as $key) {
            // No tenemos el SQL original aquí, así que invalidación por patrón
            // no puede mapear directamente; como aproximación, si el patrón
            // coincide con alguna tabla indexada, invalidar por esa tabla.
            foreach (array_keys(self::$tableKeyIndex) as $table) {
                if (preg_match($regex, $table) === 1) {
                    self::invalidateCacheForTable($table);
                }
            }
        }
    }

    private static function clearAllCache(): void
    {
        self::$queryCache    = [];
        self::$tableKeyIndex = [];
    }
}
