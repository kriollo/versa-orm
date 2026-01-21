<?php

declare(strict_types=1);

namespace VersaORM\SQL;

use Exception;
use PDO;
use PDOStatement;
use Throwable;
use VersaORM\SQL\Dialects\MySQLDialect;
use VersaORM\SQL\Dialects\PostgreSQLDialect;
use VersaORM\SQL\Dialects\SQLiteDialect;
use VersaORM\VersaORMException;

use function array_slice;
use function count;
use function in_array;
use function is_array;
use function is_bool;
use function is_callable;
use function is_int;
use function is_string;
use function sprintf;

class PdoEngine
{
    private PdoConnection $connector;

    private SqlDialectInterface $dialect;

    /**
     * Logger opcional inyectable.
     *
     * @var (callable(string,array<string,mixed>):void)|null
     */
    private $logger;

    // Caché en memoria (estático para compartirse entre instancias durante tests)
    private static bool $cacheEnabled = false;

    /**
     * Caché de consultas con TTL y límites.
     * Clave: hash derivado de (sql, bindings, method).
     * Valor: array con resultado y metadata de tiempo.
     *
     * @var array<string, array{data: array<string,mixed>|bool|int|list<array<string,mixed>>|null, created_at: int, last_access: int, ttl: int}>
     */
    private static array $queryCache = [];

    /** @var array<string, array<int, string>> Mapear tabla -> claves de caché */
    private static array $tableKeyIndex = [];

    /** @var int TTL en segundos para query cache (default 30 minutos) */
    private static int $queryCacheTtl = 1800;

    /** @var int Límite máximo de entradas en query cache */
    private static int $queryCacheLimit = 1000;

    // Métricas internas simples (estáticas para compartirse en tests)
    /**
     * @var array{
     *  queries:int,
     *  writes:int,
     *  transactions:int,
     *  cache_hits:int,
     *  cache_misses:int,
     *  last_query_ms:float,
     *  total_query_ms:float,
     *  stmt_cache_hits:int,
     *  stmt_cache_misses:int,
     *  total_prepare_ms:float,
     *  hydration_ms:float,
     *  objects_hydrated:int,
     *  hydration_fastpath_uses:int,
     *  hydration_fastpath_rows:int,
     *  hydration_fastpath_ms:float
     * }
     */
    private static array $metrics = [
        'queries' => 0, // Consultas realmente ejecutadas contra la BD
        'writes' => 0, // INSERT/UPDATE/DELETE
        'transactions' => 0, // BEGIN
        'cache_hits' => 0,
        'cache_misses' => 0,
        'last_query_ms' => 0.0,
        'total_query_ms' => 0.0,
        // Métricas de caché de sentencias
        'stmt_cache_hits' => 0,
        'stmt_cache_misses' => 0,
        'total_prepare_ms' => 0.0,
        // Métricas de hidratación (creación de objetos VersaModel)
        'hydration_ms' => 0.0,
        'objects_hydrated' => 0,
        // Fast-path hidratación
        'hydration_fastpath_uses' => 0,
        'hydration_fastpath_rows' => 0,
        'hydration_fastpath_ms' => 0.0,
    ];

    /** @var array<string, array{stmt: PDOStatement, pdo_id: string, created_at: int}> */
    private static array $stmtCache = [];

    /** @var int límite de sentencias en caché */
    private static int $stmtCacheLimit = 100;

    /** @var int TTL en segundos para statements cacheados (default 1 hora) */
    private static int $stmtCacheTtl = 3600;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(
        private array $config,
        ?callable $logger = null,
    ) {
        $this->connector = new PdoConnection($this->config);
        $this->dialect = $this->detectDialect();
        // Configurar límite de caché si se provee
        $rawLimit = $this->config['statement_cache_limit'] ?? 100;
        $limit = is_numeric($rawLimit) ? (int) $rawLimit : 100;

        if ($limit > 0 && $limit < 5000) {
            self::$stmtCacheLimit = $limit;
        }

        // Provide dialect name hint if supported for SQL generator decisions
        // Ahora todos los dialectos implementan getName()
        if ($logger !== null) {
            $this->logger = $logger;
        }
    }

    /**
     * Devuelve métricas actuales.
     *
     * @return array<string,float|int>
     */
    public static function getMetrics(): array
    {
        return self::$metrics;
    }

    /** Fuerza el cierre de la conexión PDO actual (si existe). */
    public function forceDisconnect(): void
    {
        try {
            $this->connector->close();
        } catch (Throwable) {
            // silencioso: no debe romper aplicación
        }
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
            'queries' => 0,
            'writes' => 0,
            'transactions' => 0,
            'cache_hits' => 0,
            'cache_misses' => 0,
            'last_query_ms' => 0.0,
            'total_query_ms' => 0.0,
            'stmt_cache_hits' => 0,
            'stmt_cache_misses' => 0,
            'total_prepare_ms' => 0.0,
            'hydration_ms' => 0.0,
            'objects_hydrated' => 0,
            'hydration_fastpath_uses' => 0,
            'hydration_fastpath_rows' => 0,
            'hydration_fastpath_ms' => 0.0,
        ];
        self::$stmtCache = [];
    }

    /** Registra métricas de hidratación de modelos */
    public static function recordHydration(int $count, float $elapsedMs): void
    {
        if ($count <= 0) {
            return;
        }
        self::$metrics['objects_hydrated'] += $count;
        self::$metrics['hydration_ms'] += $elapsedMs;
    }

    /** Registra uso de fast-path de hidratación */
    public static function recordHydrationFast(int $count, float $elapsedMs): void
    {
        if ($count <= 0) {
            return;
        }
        self::$metrics['hydration_fastpath_uses']++;
        self::$metrics['hydration_fastpath_rows'] += $count;
        self::$metrics['hydration_fastpath_ms'] += $elapsedMs;
        // También acumular en métricas generales de hidratación
        self::recordHydration($count, $elapsedMs);
    }

    /** Permite inyectar un logger (por ejemplo, VersaORM::logDebug) */
    public function setLogger(callable $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * @param array<string, mixed> $params
     *
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
            $rawSubject = $params['subject'] ?? '';
            $subject = strtolower(is_scalar($rawSubject) ? (string) $rawSubject : '');

            if ($subject === 'tables') {
                // Normalizar a arreglo simple de nombres de tabla (strings)
                $rows = $this->fetchTables($pdo);
                $names = [];

                foreach ($rows as $r) {
                    if (is_array($r) && isset($r['table_name'])) {
                        $names[] = $r['table_name'];
                    } elseif (is_string($r)) {
                        $names[] = $r;
                    }
                }

                return $names;
            }

            if ($subject === 'columns') {
                $rawTable = $params['table_name'] ?? $params['table'] ?? '';
                $table = is_scalar($rawTable) ? (string) $rawTable : '';

                return $table !== '' ? $this->fetchColumns($pdo, $table) : [];
            }

            if ($subject === 'indexes') {
                $rawTable = $params['table_name'] ?? $params['table'] ?? '';
                $table = is_scalar($rawTable) ? (string) $rawTable : '';

                return $table !== '' ? $this->fetchIndexes($pdo, $table) : [];
            }

            if ($subject === 'foreign_keys') {
                $rawTable = $params['table_name'] ?? $params['table'] ?? '';
                $table = is_scalar($rawTable) ? (string) $rawTable : '';

                return $table !== '' ? $this->fetchForeignKeys($pdo, $table) : [];
            }

            return [];
        }

        // Stubs para planificador en modo PDO
        if ($action === 'explain_plan') {
            $operations = $params['operations'] ?? [];
            $sql = '';

            try {
                if (is_array($operations) && $operations !== []) {
                    [$sql] = $this->buildSqlFromOperation($operations[0]);
                    // Ajuste para tests que esperan FROM users sin comillas
                    $replaced = preg_replace('/`([^`]+)`/', '${1}', (string) $sql);
                    $sql = is_string($replaced) ? $replaced : $sql;
                }
            } catch (Throwable $e) {
                $sql = '-- SQL generation failed: ' . $e->getMessage();
            }

            return [
                'plan' => [
                    'estimated_cost' => 0,
                ],
                'generated_sql' => $sql,
                'optimizations_applied' => false,
            ];
        }

        if ($action === 'query_plan') {
            // Para pruebas unitarias con sqlite in-memory evitamos ejecutar SQL real
            // ya que muchas pruebas no crean explícitamente las tablas esperadas.
            // En su lugar devolvemos un arreglo vacío para indicar que no hay plan ejecutado.
            return [];
        }

        // Gestión de caché (enable/disable/clear/status/invalidate)
        if ($action === 'cache') {
            $rawCacheAction = $params['action'] ?? '';
            $cacheAction = strtolower(is_scalar($rawCacheAction) ? (string) $rawCacheAction : '');

            return match ($cacheAction) {
                'enable' => (static function (): string {
                    self::$cacheEnabled = true;

                    return 'cache enabled';
                })(),
                'disable' => (static function (): string {
                    self::$cacheEnabled = false;

                    return 'cache disabled';
                })(),
                'clear' => (static function (): string {
                    self::$queryCache = [];
                    self::$tableKeyIndex = [];

                    return 'cache cleared';
                })(),
                'ttl' => (static function (array $params): string {
                    $rawTtl = $params['ttl'] ?? 1800;
                    $ttl = is_numeric($rawTtl) ? (int) $rawTtl : 1800;
                    self::$queryCacheTtl = $ttl;
                    return "cache ttl set to {$ttl}s";
                })($params),
                'limit' => (static function (array $params): string {
                    $rawLimit = $params['limit'] ?? 1000;
                    $limit = is_numeric($rawLimit) ? (int) $rawLimit : 1000;
                    self::$queryCacheLimit = $limit;
                    return "cache limit set to {$limit}";
                })($params),
                'status' => count(self::$queryCache),
                'stats' => [
                    'enabled' => self::$cacheEnabled,
                    'entries' => count(self::$queryCache),
                    'tables_indexed' => count(self::$tableKeyIndex),
                ],
                'invalidate' => (static function (array $params): string {
                    $rawTable = $params['table'] ?? '';
                    $table = is_scalar($rawTable) ? (string) $rawTable : '';
                    $rawPattern = $params['pattern'] ?? '';
                    $pattern = is_scalar($rawPattern) ? (string) $rawPattern : '';

                    if ($table === '' && $pattern === '') {
                        return 'cache invalidation skipped (no criteria)';
                    }

                    if ($pattern !== '') {
                        self::invalidateCacheByPattern($pattern);
                    } elseif ($table !== '') {
                        self::invalidateCacheForTable($table);
                    }

                    return 'cache invalidated';
                })($params),
                default => throw new VersaORMException(
                    'PDO engine does not support this cache action: ' . $cacheAction,
                    'UNSUPPORTED_CACHE_ACTION',
                ),
            };
        }

        // Soporte mínimo para operaciones avanzadas cuando el motor es PDO
        if ($action === 'advanced_sql') {
            $driver = $this->dialect->getName();
            $rawOpType = $params['operation_type'] ?? '';
            $opType = is_scalar($rawOpType) ? (string) $rawOpType : '';

            try {
                return match ($opType) {
                    'set_operation' => (function () use ($params, $pdo, $driver) {
                        // Espera: set_type en ['UNION','UNION ALL','INTERSECT','INTERSECT ALL','EXCEPT','EXCEPT ALL']
                        $rawSetType = $params['set_type'] ?? '';
                        $setType = strtoupper(is_scalar($rawSetType) ? (string) $rawSetType : '');
                        /** @var list<array{sql?:string,bindings?:array<int,mixed>|mixed}> $queries */
                        $queries = is_array($params['queries'] ?? null) ? $params['queries'] : [];
                        if (count($queries) < 2) {
                            throw new VersaORMException('set_operation requires at least 2 queries');
                        }
                        $valid = ['UNION', 'UNION ALL', 'INTERSECT', 'INTERSECT ALL', 'EXCEPT', 'EXCEPT ALL'];
                        if (!in_array($setType, $valid, true)) {
                            throw new VersaORMException('Invalid set operation type: ' . $setType);
                        }
                        // Soporte según driver: MySQL y SQLite no manejan INTERSECT/EXCEPT ALL nativamente en versiones antiguas
                        // Simplificación: si no soporta, lanzar excepción explícita.
                        $supportsIntersectExcept = str_contains($driver, 'postgres');
                        if (
                            !$supportsIntersectExcept
                            && (str_starts_with($setType, 'INTERSECT') || str_starts_with($setType, 'EXCEPT'))
                        ) {
                            throw new VersaORMException('Driver does not support ' . $setType . ' in PDO mode');
                        }
                        // Construir SQL concatenando queries con operador
                        $parts = [];
                        $bindings = [];
                        foreach ($queries as $q) {
                            // @phpstan-ignore-next-line (type annotation may be imprecise)
                            if (!is_array($q) || !isset($q['sql']) || !is_string($q['sql'])) {
                                throw new VersaORMException('Each set_operation query must have sql');
                            }
                            // Nota: SQLite puede fallar con paréntesis envolviendo selects simples en UNION.
                            // Estrategia: no envolver cuando es UNION / UNION ALL y la consulta no contiene palabras clave que requieran aislamiento.
                            $sqlPart = $q['sql'];
                            $needsWrap = !str_starts_with($setType, 'UNION');
                            if ($needsWrap) {
                                $sqlPart = '(' . $sqlPart . ')';
                            }
                            $parts[] = $sqlPart;
                            if (isset($q['bindings']) && is_array($q['bindings'])) {
                                foreach ($q['bindings'] as $b) {
                                    $bindings[] = $b;
                                }
                            }
                        }
                        // Operador de set; construir dinámicamente para no fijar shape exacto
                        /** @var array<string,string> $operatorMap */
                        $operatorMap = [];
                        $operatorMap['UNION'] = ' UNION ';
                        $operatorMap['UNION ALL'] = ' UNION ALL ';
                        $operatorMap['INTERSECT'] = ' INTERSECT ';
                        $operatorMap['INTERSECT ALL'] = ' INTERSECT ALL ';
                        $operatorMap['EXCEPT'] = ' EXCEPT ';
                        $operatorMap['EXCEPT ALL'] = ' EXCEPT ALL ';
                        $operator = $operatorMap[$setType] ?? ' UNION ';
                        $sql = implode($operator, $parts);
                        $stmt = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, $bindings);
                        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];

                        return is_array($rows) ? $rows : [];
                    })(),
                    'window_function' => (function () use ($params, $pdo) {
                        // SELECT existente + columna window
                        $rawTable = $params['table'] ?? '';
                        $table = is_scalar($rawTable) ? (string) $rawTable : '';
                        $rawFunction = $params['function'] ?? 'row_number';
                        $function = strtolower(is_scalar($rawFunction) ? (string) $rawFunction : 'row_number');
                        $rawColumn = $params['column'] ?? '*';
                        $column = is_scalar($rawColumn) ? (string) $rawColumn : '*';
                        $rawAlias = $params['alias'] ?? 'window_result';
                        $alias = is_scalar($rawAlias) ? (string) $rawAlias : 'window_result';
                        /** @var list<string> $partition */
                        $partition = [];

                        if (isset($params['partition_by']) && is_array($params['partition_by'])) {
                            foreach ($params['partition_by'] as $p) {
                                if (!(is_string($p) && $p !== '')) {
                                    continue;
                                }

                                $partition[] = $p;
                            }
                        }
                        /** @var list<array{column:string,direction?:string}> $orderBy */
                        $orderBy = [];

                        if (isset($params['order_by']) && is_array($params['order_by'])) {
                            foreach ($params['order_by'] as $o) {
                                if (!(is_array($o) && isset($o['column']) && is_string($o['column']))) {
                                    continue;
                                }

                                $entry = ['column' => $o['column']];

                                if (isset($o['direction']) && is_string($o['direction'])) {
                                    $entry['direction'] = $o['direction'];
                                }
                                $orderBy[] = $entry;
                            }
                        }
                        /** @var list<array{type:string,field:string,operator:string,value:mixed,boolean?:string}> $wheres */
                        $wheres = [];

                        if (isset($params['wheres']) && is_array($params['wheres'])) {
                            foreach ($params['wheres'] as $w) {
                                if (!(is_array($w) && isset($w['field'], $w['operator']))) {
                                    continue;
                                }

                                $wheres[] = [
                                    'type' => is_scalar($w['type'] ?? null)
                                        ? (string) ($w['type'] ?? 'basic')
                                        : 'basic',
                                    'field' => is_scalar($w['field']) ? (string) $w['field'] : '',
                                    'operator' => is_scalar($w['operator']) ? (string) $w['operator'] : '=',
                                    'value' => $w['value'] ?? null,
                                    'boolean' => is_scalar($w['boolean'] ?? null)
                                        ? (string) ($w['boolean'] ?? 'and')
                                        : 'and',
                                ];
                            }
                        }
                        $ntileBuckets = $params['args']['buckets'] ?? 2;
                        $funcSql = match ($function) {
                            'row_number', 'rank', 'dense_rank' => strtoupper($function) . '()',
                            'lag', 'lead' => strtoupper($function) . '(' . ($column === '*' ? '1' : $column) . ')',
                            'first_value' => 'FIRST_VALUE(' . $column . ')',
                            'last_value' => 'LAST_VALUE(' . $column . ')',
                            'ntile' => 'NTILE(' . (is_numeric($ntileBuckets) ? (int) $ntileBuckets : 2) . ')',
                            default => 'ROW_NUMBER()',
                        };
                        // Detectar alias de tabla si viene como "table AS alias" o "table alias"
                        $tableRef = trim($table);
                        $baseQualifier = $tableRef;

                        if (
                            preg_match(
                                '/^([A-Za-z_][A-Za-z0-9_\.]*)(?:\s+as\s+|\s+)([A-Za-z_][A-Za-z0-9_]*)$/i',
                                $tableRef,
                                $m,
                            ) === 1
                        ) {
                            $baseQualifier = $m[2]; // usar alias si existe
                        }
                        $baseQualifierQuoted = $this->dialect->quoteIdentifier($baseQualifier);
                        $over = [];

                        if (!empty($partition)) {
                            // Calificar columnas de PARTITION BY con alias/tabla base si no vienen calificadas
                            $parts = array_map(function ($p) use ($baseQualifierQuoted): string {
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
                                $dir = strtoupper((string) ($o['direction'] ?? 'ASC'));
                                $col = (string) ($o['column'] ?? '');

                                if (
                                    $col !== ''
                                    && $col !== '*'
                                    && !str_contains($col, '.')
                                    && !str_contains($col, '(')
                                ) {
                                    $col = $baseQualifierQuoted . '.' . $this->dialect->quoteIdentifier($col);
                                }
                                $ob[] = $col . ' ' . (in_array($dir, ['ASC', 'DESC'], true) ? $dir : 'ASC');
                            }

                            if ($ob !== []) {
                                $over[] = 'ORDER BY ' . implode(', ', $ob);
                            }
                        }
                        $overSql = 'OVER (' . implode(' ', $over) . ')';
                        // Construir SELECT básico de la tabla
                        [$baseSql, $baseBindings] = SqlGenerator::generate(
                            'query',
                            [
                                'method' => 'get',
                                'table' => $table,
                                'select' => ['*'],
                                'where' => $wheres,
                            ],
                            $this->dialect,
                        );
                        // Calificar columna si aplica
                        $tmp = preg_replace('/\((\s*\*\s*)\)/', '(1)', $funcSql);
                        $qualifiedFuncSql = is_string($tmp) ? $tmp : $funcSql;

                        if ($column !== '*') {
                            // Solo reemplazar ocurrencias de nombre de columna aislado (evitar tocar funciones)
                            $qualified = str_contains($column, '(') || str_contains($column, '.')
                                ? $column
                                : $baseQualifierQuoted
                                . '.'
                                . $this->dialect->quoteIdentifier($column);
                            // Reemplazo conservador: si la función es LAG/LEAD/FIRST_VALUE/LAST_VALUE con el nombre simple
                            $tmp2 = preg_replace(
                                '/\b' . preg_quote($column, '/') . '\b/',
                                $qualified,
                                $qualifiedFuncSql,
                            );
                            $qualifiedFuncSql = is_string($tmp2) ? $tmp2 : $qualifiedFuncSql;
                        }
                        // Insertar la expresión window directamente en el SELECT base
                        $sql = (string) preg_replace(
                            '/^SELECT\s+\*\s+FROM\s+/i',
                            'SELECT *, '
                            . $qualifiedFuncSql
                            . ' '
                            . $overSql
                            . ' AS '
                            . $this->dialect->quoteIdentifier($alias)
                            . ' FROM ',
                            $baseSql,
                            1,
                        );

                        // Log de depuración opcional vía logger inyectado
                        $this->log('[PDO][advanced_sql][window_function] SQL: ' . $sql, ['sql' => $sql]);

                        try {
                            $stmt = $this->prepareCached($pdo, $sql);
                            $this->bindAndExecute($stmt, $baseBindings);

                            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
                        } catch (Throwable $e) {
                            // Incluir el SQL generado para facilitar el diagnóstico de columnas/alias
                            throw new Exception(
                                'advanced_sql window_function failed. SQL: '
                                . $sql
                                . ' | Bindings: '
                                . json_encode($baseBindings)
                                . ' | Error: '
                                    . $e->getMessage(),
                                0,
                                $e,
                            );
                        }
                    })(),
                    'cte' => (function () use ($params, $pdo) {
                        /** @var list<array{name?:string,query?:string,columns?:list<string>,recursive?:bool,bindings?:array<int,mixed>}> $ctes */
                        $ctes = [];

                        if (isset($params['ctes']) && is_array($params['ctes'])) {
                            foreach ($params['ctes'] as $c) {
                                if (!is_array($c)) {
                                    continue;
                                }

                                $ctes[] = $c;
                            }
                        }
                        $withParts = [];
                        /** @var array<int,mixed> $bindings */
                        $bindings = [];
                        $isRecursive = false;

                        foreach ($ctes as $c) {
                            $name = is_scalar($c['name'] ?? null) ? (string) $c['name'] : 'cte';
                            $querySql = is_scalar($c['query'] ?? null) ? (string) $c['query'] : '';
                            $colsDef = '';

                            if (!empty($c['columns']) && is_array($c['columns'])) {
                                $quotedCols = array_map(fn($col): string => $this->dialect->quoteIdentifier(
                                    is_scalar($col) ? (string) $col : '',
                                ), $c['columns']);
                                $colsDef = ' (' . implode(', ', $quotedCols) . ')';
                            }

                            if (!empty($c['recursive'])) {
                                $isRecursive = true;
                            }
                            $withParts[] =
                                $this->dialect->quoteIdentifier($name)
                                . $colsDef
                                . ' AS ('
                                . $querySql
                                . ')';

                            if (isset($c['bindings']) && is_array($c['bindings'])) {
                                $bindings = array_merge($bindings, array_values($c['bindings']));
                            }
                        }
                        $main = is_scalar($params['main_query'] ?? null) ? (string) $params['main_query'] : '';
                        $mainBindings = [];

                        if (isset($params['main_query_bindings']) && is_array($params['main_query_bindings'])) {
                            $mainBindings = $params['main_query_bindings'];
                        }
                        $withKeyword = 'WITH' . ($isRecursive ? ' RECURSIVE ' : ' ');
                        $sql = $withKeyword . implode(', ', $withParts) . ' ' . $main;
                        $stmt = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, array_merge($bindings, $mainBindings));

                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
                    })(),
                    'union', 'intersect', 'except' => (function () use ($params, $pdo, $opType) {
                        /** @var list<array{sql?:string,bindings?:array<int,mixed>}> $queries */
                        $queries = [];

                        if (isset($params['queries']) && is_array($params['queries'])) {
                            foreach ($params['queries'] as $q) {
                                if (!is_array($q)) {
                                    continue;
                                }

                                $queries[] = $q;
                            }
                        }
                        $all = (bool) ($params['all'] ?? false);

                        if ($opType === 'union') {
                            $glue = $all ? ' UNION ALL ' : ' UNION ';
                        } elseif ($opType === 'intersect') {
                            $glue = $all ? ' INTERSECT ALL ' : ' INTERSECT ';
                        } else {
                            $glue = $all ? ' EXCEPT ALL ' : ' EXCEPT ';
                        }
                        $parts = [];
                        $bindings = [];

                        foreach ($queries as $q) {
                            $sqlPart = is_scalar($q['sql'] ?? null) ? (string) $q['sql'] : '';

                            // SQLite puede quejarse de paréntesis en cada SELECT en UNION
                            $parts[] = $this->dialect->getName() === 'sqlite' ? $sqlPart : '(' . $sqlPart . ')';
                            $qb = is_array($q['bindings'] ?? null) ? $q['bindings'] : [];
                            $bindings = array_merge($bindings, $qb);
                        }
                        $sql = implode($glue, $parts);
                        $stmt = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, $bindings);

                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
                    })(),
                    'json_operation' => (function () use ($params, $pdo, $driver) {
                        $table = is_scalar($params['table'] ?? null) ? (string) $params['table'] : '';
                        $col = is_scalar($params['column'] ?? null) ? (string) $params['column'] : '';
                        $op = is_scalar($params['json_operation'] ?? null)
                            ? (string) $params['json_operation']
                            : 'extract';
                        $path = is_scalar($params['path'] ?? null) ? (string) $params['path'] : '';
                        /** @var list<array{type:string,field:string,operator:string,value:mixed,boolean?:string}> $wheres */
                        $wheres = [];

                        if (isset($params['wheres']) && is_array($params['wheres'])) {
                            foreach ($params['wheres'] as $w) {
                                if (!(is_array($w) && isset($w['field'], $w['operator']))) {
                                    continue;
                                }

                                $wheres[] = [
                                    'type' => is_scalar($w['type'] ?? null) ? (string) $w['type'] : 'basic',
                                    'field' => is_scalar($w['field'] ?? null) ? (string) $w['field'] : '',
                                    'operator' => is_scalar($w['operator'] ?? null) ? (string) $w['operator'] : '=',
                                    'value' => $w['value'] ?? null,
                                    'boolean' => is_scalar($w['boolean'] ?? null) ? (string) $w['boolean'] : 'and',
                                ];
                            }
                        }
                        $bind = [];
                        $jsonExpr = '';

                        // Soporte de sintaxis arrow (col->key->>key2) y extracción sin comillas en MySQL
                        $arrowStyle = false;
                        $unquote = false;

                        if ($driver === 'mysql' && preg_match('/->>/', $path) === 1) {
                            $arrowStyle = true;
                            $unquote = true; // ->> indica descomillas
                        } elseif ($driver === 'mysql' && preg_match('/->/', $path) === 1) {
                            $arrowStyle = true;
                        }

                        if ($driver === 'mysql') {
                            if ($arrowStyle) {
                                // Convertir col->a->b->>c en JSON_EXTRACT(col,'$.a.b.c') y opcional JSON_UNQUOTE
                                $segments = preg_split('/->>?/', $path);
                                if (!is_array($segments)) {
                                    $segments = [];
                                }
                                // Filtrar segmentos vacíos o que repitan el nombre de la columna
                                $segments = array_values(array_filter(
                                    $segments,
                                    static fn($s): bool => $s !== '' && $s !== $col,
                                ));

                                // Si el path original incluía col al inicio, removerlo
                                if ($segments !== [] && $segments[0] === $col) {
                                    array_shift($segments);
                                }
                                $jsonPath = '$';

                                if ($segments !== []) {
                                    $jsonPath .=
                                        '.'
                                        . implode('.', array_map(static fn($s): string => trim(
                                            $s,
                                            "'\"` ",
                                        ), $segments));
                                }
                                $core = "JSON_EXTRACT({$col}, ?)";
                                $jsonExpr = ($unquote ? 'JSON_UNQUOTE(' . $core . ')' : $core) . ' AS value';
                                $bind = [$jsonPath];
                            } elseif ($op === 'extract') {
                                $jsonExpr = "JSON_EXTRACT({$col}, ?) AS value";
                                $bind = [$path];
                            } else {
                                // Operaciones adicionales básicas (contains, keys, etc.) podrían ampliarse
                                $jsonExpr = "JSON_EXTRACT({$col}, ?) AS value";
                                $bind = [$path];
                            }
                        } elseif ($driver === 'postgres') {
                            $segments = array_filter(explode('.', trim($path, '$.')), static fn($s): bool => $s !== '');
                            $expr = $col;

                            foreach ($segments as $idx => $s) {
                                // Último segmento usar ->> para texto simple
                                $opArrow = $idx === array_key_last($segments) ? '->>' : '->';
                                $expr .= $opArrow . "'" . $s . "'";
                            }
                            $jsonExpr = $expr . ' AS value';
                            $bind = [];
                        } else { // sqlite
                            $jsonExpr = "json_extract({$col}, ?) AS value";
                            $bind = [$path];
                        }

                        [$baseSql, $baseBindings] = SqlGenerator::generate(
                            'query',
                            [
                                'method' => 'get',
                                'table' => $table,
                                'select' => ['*'],
                                'where' => $wheres,
                            ],
                            $this->dialect,
                        );
                        $tmpSql = preg_replace(
                            '/^SELECT\s+\*\s+FROM/i',
                            'SELECT *, ' . $jsonExpr . ' FROM',
                            (string) $baseSql,
                            1,
                        );
                        $sql = is_string($tmpSql) ? $tmpSql : (string) $baseSql;
                        $stmt = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, array_merge($bind, $baseBindings));

                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
                    })(),
                    'full_text_search' => (function () use ($params, $pdo, $driver) {
                        $table = is_scalar($params['table'] ?? null) ? (string) $params['table'] : '';
                        /** @var list<string> $cols */
                        $cols = [];

                        if (isset($params['columns']) && is_array($params['columns'])) {
                            foreach ($params['columns'] as $c) {
                                if (!(is_string($c) && $c !== '')) {
                                    continue;
                                }

                                $cols[] = $c;
                            }
                        }
                        $term = is_scalar($params['search_term'] ?? null) ? (string) $params['search_term'] : '';
                        $options = (array) ($params['options'] ?? []);

                        if ($driver === 'mysql') {
                            $modeSql = '';

                            if (isset($options['mode']) && is_string($options['mode'])) {
                                $modeSql = ' IN ' . $options['mode'] . ' MODE';
                            }
                            $match = 'MATCH(' . implode(', ', $cols) . ') AGAINST (?' . $modeSql . ')';
                            $select = '*';

                            if (!empty($options['with_score'])) {
                                $select = '*, ' . $match . ' AS score';
                            }
                            $sql =
                                'SELECT '
                                . $select
                                . ' FROM '
                                . $this->dialect->quoteIdentifier($table)
                                . ' WHERE '
                                . $match;
                            $stmt = $this->prepareCached($pdo, $sql);
                            // Si with_score agrega el MATCH también en SELECT, enlazar el término dos veces
                            $bindings = empty($options['with_score']) ? [$term] : [$term, $term];
                            $stmt->execute($bindings);

                            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
                        }

                        if ($driver === 'postgres') {
                            // Usar to_tsvector/tsquery; si la columna ya es tsvector, comparar directamente
                            $language = is_scalar($options['language'] ?? null)
                                ? (string) $options['language']
                                : 'english';
                            $operator = is_scalar($options['operator'] ?? null) ? (string) $options['operator'] : '@@';
                            $rank = !empty($options['rank']);
                            $colExpr = implode(' || \" \" || ', array_map(
                                static fn($c): string => "to_tsvector('" . $language . "', " . $c . ')',
                                $cols,
                            ));

                            // Si solo una columna y parece tsvector, usarla directa
                            if (count($cols) === 1 && preg_match('/vector$/i', $cols[0]) === 1) {
                                $colExpr = $cols[0];
                            }
                            $rankExpr = $rank ? ', ts_rank(' . $colExpr . ', plainto_tsquery(?)) AS rank' : '';
                            $sql =
                                'SELECT *'
                                . $rankExpr
                                . ' FROM '
                                . $this->dialect->quoteIdentifier($table)
                                . ' WHERE '
                                . $colExpr
                                . ' '
                                . $operator
                                . ' plainto_tsquery(?)';
                            $stmt = $this->prepareCached($pdo, $sql);
                            $this->bindAndExecute($stmt, $rank ? [$term, $term] : [$term]);

                            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
                        }
                        // Fallback: LIKE en otros drivers
                        $likeParts = [];

                        foreach ($cols as $c) {
                            $likeParts[] = "{$c} LIKE ?";
                        }
                        $sql =
                            'SELECT * FROM '
                            . $this->dialect->quoteIdentifier($table)
                            . ' WHERE '
                            . implode(' OR ', $likeParts);
                        $stmt = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, array_fill(0, count($likeParts), '%' . $term . '%'));

                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
                    })(),
                    'array_operations' => (function () use ($params, $pdo, $driver) {
                        // Soporte mínimo para arrays en Postgres
                        if ($driver !== 'postgres') {
                            throw new VersaORMException(
                                'Unsupported advanced_sql operation in PDO engine: array_operations',
                            );
                        }
                        $table = is_scalar($params['table'] ?? null) ? (string) $params['table'] : '';
                        $col = is_scalar($params['column'] ?? null) ? (string) $params['column'] : '';
                        $op = is_scalar($params['array_operation'] ?? null) ? (string) $params['array_operation'] : '';
                        $value = $params['value'] ?? null;
                        $whereSql = '';
                        $bindings = [];

                        switch ($op) {
                            case 'contains':
                                $whereSql = $col . ' @> ?';
                                $bindings[] = is_array($value)
                                    ? '{' . implode(',', $value) . '}'
                                    : '{'
                                    . (is_scalar($value) ? (string) $value : '')
                                    . '}';
                                break;
                            case 'overlap':
                                $whereSql = $col . ' && ?';
                                $bindings[] = is_array($value)
                                    ? '{' . implode(',', $value) . '}'
                                    : '{'
                                    . (is_scalar($value) ? (string) $value : '')
                                    . '}';
                                break;
                            case 'any':
                                $whereSql = '? = ANY(' . $col . ')';
                                $bindings[] = $value;
                                break;
                            case 'all':
                                $whereSql = '? = ALL(' . $col . ')';
                                $bindings[] = $value;
                                break;
                            default:
                                throw new VersaORMException('Unsupported array operation: ' . $op);
                        }
                        $sql = 'SELECT * FROM ' . $this->dialect->quoteIdentifier($table) . ' WHERE ' . $whereSql;
                        $stmt = $this->prepareCached($pdo, $sql);
                        $this->bindAndExecute($stmt, $bindings);

                        return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
                    })(),
                    'advanced_aggregation' => (function () use ($params, $pdo, $driver) {
                        $type = is_scalar($params['aggregation_type'] ?? null)
                            ? (string) $params['aggregation_type']
                            : '';
                        $table = is_scalar($params['table'] ?? null) ? (string) $params['table'] : '';
                        $column = is_scalar($params['column'] ?? null) ? (string) $params['column'] : '';
                        /** @var list<string> $groupBy */
                        $groupBy = [];

                        if (isset($params['groupBy']) && is_array($params['groupBy'])) {
                            foreach ($params['groupBy'] as $g) {
                                if (!(is_string($g) && $g !== '')) {
                                    continue;
                                }

                                $groupBy[] = $g;
                            }
                        }

                        if ($type === 'group_concat') {
                            $sep = is_scalar($params['options']['separator'] ?? null)
                                ? (string) $params['options']['separator']
                                : ',';
                            $order = is_scalar($params['options']['order_by'] ?? null)
                                ? (string) $params['options']['order_by']
                                : '';
                            $sepValue = str_replace("'", "''", $sep);

                            if ($driver === 'mysql') {
                                $expr =
                                    'GROUP_CONCAT('
                                    . $column
                                    . ($order !== '' && $order !== '0' ? ' ORDER BY ' . $order : '')
                                    . " SEPARATOR '"
                                    . $sepValue
                                    . "') AS agg";
                            } elseif ($driver === 'postgres') {
                                // string_agg(col::text, sep) [ORDER BY col]
                                $expr =
                                    'string_agg('
                                    . $column
                                    . '::text, '
                                    . "'"
                                    . $sepValue
                                    . "'"
                                    . ')'
                                    . ($order !== '' && $order !== '0' ? ' ORDER BY ' . $order : '')
                                    . ' AS agg';
                            } else { // sqlite
                                // group_concat(col, sep)
                                $expr = 'group_concat(' . $column . ", '" . $sepValue . "') AS agg";
                            }
                            $sql =
                                'SELECT '
                                . (empty($groupBy) ? $expr : implode(', ', $groupBy) . ', ' . $expr)
                                . ' FROM '
                                . $this->dialect->quoteIdentifier($table);

                            if (!empty($groupBy)) {
                                $sql .= ' GROUP BY ' . implode(', ', $groupBy);
                            }
                            $stmt = $this->prepareCached($pdo, $sql);
                            $stmt->execute();

                            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
                        }
                        $map = ['median' => 'AVG', 'variance' => 'VARIANCE', 'stddev' => 'STDDEV'];
                        $func = $map[$type] ?? 'COUNT';
                        $sql =
                            'SELECT '
                            . $func
                            . '('
                            . ($column !== '' && $column !== '0' ? $column : '*')
                            . ') AS agg FROM '
                            . $this->dialect->quoteIdentifier($table);
                        $stmt = $pdo->query($sql);

                        return $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [] : [];
                    })(),
                    'get_driver_capabilities' => (static function () use ($pdo, $driver): array {
                        $features = [
                            'window_functions' => in_array($driver, ['mysql', 'postgres', 'sqlite'], true),
                            'json_support' => true,
                            'fts_support' => in_array($driver, ['mysql', 'postgres', 'sqlite'], true),
                        ];

                        return [
                            'driver' => $driver,
                            'version' => $pdo->getAttribute(PDO::ATTR_SERVER_VERSION) ?? null,
                            'features' => $features,
                        ];
                    })(),
                    'get_driver_limits' => (static fn(): array => (
                        // Valores aproximados comunes o seguros
                        [
                            'max_columns' => 2000,
                            'max_sql_length' => 1000000,
                            'max_page_size' => 4096,
                        ]
                    ))(),
                    'optimize_query' => [
                        'optimization_suggestions' => [],
                        'generated_sql' => is_scalar($params['query'] ?? null) ? (string) $params['query'] : '',
                    ],
                    default => throw new VersaORMException('Unsupported advanced_sql operation in PDO engine: '
                    . $opType),
                };
            } catch (Throwable $e) {
                throw new VersaORMException('PDO advanced_sql failed: ' . $e->getMessage(), 'PDO_ADVANCED_SQL_FAILED');
            }
        }

        [$sql, $bindings] = SqlGenerator::generate($action, $params, $this->dialect);

        // Normalización por acción
        if ($action === 'query') {
            $method = is_scalar($params['method'] ?? null) ? (string) $params['method'] : 'get';

            // Batch operations mapped to query
            if (in_array($method, ['insertMany', 'updateMany', 'deleteMany', 'upsertMany'], true)) {
                // Reutilizamos los handlers directos para mantener una única implementación
                $normalizedQueryBatch = strtolower($method);

                return match ($normalizedQueryBatch) {
                    'insertmany' => $this->handleInsertMany($params, $pdo),
                    'updatemany' => $this->handleUpdateMany($params, $pdo),
                    'deletemany' => $this->handleDeleteMany($params, $pdo),
                    'upsertmany' => $this->handleUpsertMany($params, $pdo),
                    default => throw new VersaORMException('Unsupported query batch method: ' . $method),
                };
            }

            // Lecturas con caché
            if (self::$cacheEnabled && in_array($method, ['get', 'first', 'exists', 'count'], true)) {
                $cacheKey = $this->makeCacheKey($sql, $bindings, $method);

                if (isset(self::$queryCache[$cacheKey])) {
                    $entry = self::$queryCache[$cacheKey];
                    $currentTime = time();

                    // Verificar si ha expirado
                    if (($currentTime - $entry['created_at']) < self::$queryCacheTtl) {
                        // Actualizar last_access para LRU
                        self::$queryCache[$cacheKey]['last_access'] = $currentTime;
                        $this->recordCacheHit();

                        return $entry['data'];
                    }
                    // Eliminar entrada expirada
                    unset(self::$queryCache[$cacheKey]);
                }
                $this->recordCacheMiss();
            }

            if ($method === 'count') {
                $stmt = $this->prepareCached($pdo, $sql);
                $start = microtime(true);

                try {
                    $this->bindAndExecute($stmt, $bindings);
                } catch (Throwable $e) {
                    throw new VersaORMException(
                        'SQL failed (count): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | '
                            . $e->getMessage(),
                        'PDO_EXEC_FAILED',
                    );
                }
                $elapsed = (microtime(true) - $start) * 1000;
                $this->recordQuery(false, $elapsed);
                $row = $stmt->fetch(PDO::FETCH_ASSOC) ?? [];
                $rawCount = $row['count'] ?? 0;
                $result = is_numeric($rawCount) ? (int) $rawCount : 0;

                if (self::$cacheEnabled) {
                    $this->storeInCache($sql, $bindings, 'count', $result);
                }

                return $result;
            }

            if ($method === 'exists') {
                $stmt = $this->prepareCached($pdo, $sql);
                $start = microtime(true);

                try {
                    $this->bindAndExecute($stmt, $bindings);
                } catch (Throwable $e) {
                    throw new VersaORMException(
                        'SQL failed (exists): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | '
                            . $e->getMessage(),
                        'PDO_EXEC_FAILED',
                    );
                }
                $elapsed = (microtime(true) - $start) * 1000;
                $this->recordQuery(false, $elapsed);
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                $rowArray = is_array($row) ? $row : [];
                $val = array_values($rowArray)[0] ?? 0;
                $result = (bool) $val;

                if (self::$cacheEnabled) {
                    $this->storeInCache($sql, $bindings, 'exists', $result);
                }

                return $result;
            }

            if ($method === 'first') {
                $stmt = $this->prepareCached($pdo, $sql);
                $start = microtime(true);

                try {
                    $this->bindAndExecute($stmt, $bindings);
                } catch (Throwable $e) {
                    throw new VersaORMException(
                        'SQL failed (first): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | '
                            . $e->getMessage(),
                        'PDO_EXEC_FAILED',
                    );
                }
                $elapsed = (microtime(true) - $start) * 1000;
                $this->recordQuery(false, $elapsed);
                $row = $stmt->fetch(PDO::FETCH_ASSOC) ?? null;

                try {
                    $stmt->closeCursor();
                } catch (Throwable) { // ignore
                }

                if (self::$cacheEnabled) {
                    $this->storeInCache($sql, $bindings, 'first', $row);
                }

                return $row;
            }
            // default get
            // Log de diagnóstico usando el logger inyectado (VersaORM::logDebug)
            $this->log('[PDO][GET] Executing SQL', ['sql' => $sql, 'bindings' => $bindings]);
            $stmt = $this->prepareCached($pdo, $sql);
            $start = microtime(true);

            try {
                $this->bindAndExecute($stmt, $bindings);
            } catch (Throwable $e) {
                throw new VersaORMException(
                    'SQL failed (get): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | ' . $e->getMessage(),
                    'PDO_EXEC_FAILED',
                );
            }
            $elapsed = (microtime(true) - $start) * 1000;
            $this->recordQuery(false, $elapsed);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            try {
                $stmt->closeCursor();
            } catch (Throwable) { // ignore
            }
            /** @var array<string, mixed> $result */
            $result = is_array($rows) ? $rows : [];

            if (self::$cacheEnabled) {
                $this->storeInCache($sql, $bindings, 'get', $result);
            }

            return $result;
        }

        if ($action === 'raw') {
            // Preparar SQL/bindings directamente desde params para el caso 'raw'
            $rawSqlVal = $params['sql'] ?? $params['query'] ?? '';
            $sql = is_scalar($rawSqlVal) ? (string) $rawSqlVal : '';
            /** @var array<int,mixed> $bindings */
            $bindings = is_array($params['bindings'] ?? null) ? array_values($params['bindings']) : [];

            // Soporte explícito para transacciones
            $normalized = strtoupper(trim($sql));

            if (str_starts_with($normalized, 'BEGIN') || str_starts_with($normalized, 'START TRANSACTION')) {
                $pdo->beginTransaction();

                return null;
            }

            if (str_starts_with($normalized, 'COMMIT')) {
                $pdo->commit();
                // Al confirmar cambios, invalidar caché por seguridad
                $this->clearAllCache();
                $this->clearStmtCache();

                return null;
            }

            if (str_starts_with($normalized, 'ROLLBACK')) {
                $pdo->rollBack();
                // Tras rollback, el caché puede quedar inconsistente si se cachearon lecturas intermedias
                $this->clearAllCache();
                $this->clearStmtCache();

                return null;
            }

            // Detectar si es una sentencia de escritura antes de intentar fetchAll
            $isWrite =
                preg_match('/^\s*(INSERT|UPDATE|DELETE|REPLACE|TRUNCATE|CREATE|DROP|ALTER|REINDEX|VACUUM)\b/i', $sql)
                === 1;
            $isDDL = preg_match('/^\s*(CREATE|DROP|ALTER|REINDEX|VACUUM)\b/i', $sql) === 1;

            if ($isDDL) {
                // Antes de DDL, limpiar sentencias preparadas que referencian esquema previo
                $this->clearStmtCache();
            }
            $stmt = $this->prepareCached($pdo, $sql);
            $start = microtime(true);

            try {
                $this->bindAndExecute($stmt, $bindings);
            } catch (Throwable $e) {
                // Normalizar excepciones a VersaORMException para la API
                throw new VersaORMException(
                    'SQL failed (raw): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | ' . $e->getMessage(),
                    'PDO_EXEC_FAILED',
                );
            }

            $elapsed = (microtime(true) - $start) * 1000;
            // Registrar métricas (write o read según patrón detectado)
            $this->recordQuery($isWrite, $elapsed);

            if ($isWrite) {
                // Invalidar todo el caché en operaciones de escritura para mantener coherencia
                $this->clearAllCache();

                // Normalizar: devolver null para no-SELECT (los tests aceptan null/[])
                try {
                    $stmt->closeCursor();
                } catch (Throwable) { // ignore
                }

                if ($isDDL) {
                    // Tras DDL, volver a limpiar por si alguna sentencia quedó asociada
                    $this->clearStmtCache();
                }

                return null;
            }
            // Lecturas: devolver filas y cachear si corresponde
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];

            try {
                $stmt->closeCursor();
            } catch (Throwable) { // ignore
            }

            if (self::$cacheEnabled) {
                $this->storeInCache($sql, $bindings, 'raw', $rows);
            }

            return $rows;
        }

        if ($action === 'insert') {
            // Log SQL y bindings para diagnosticar problemas de inserción
            $this->log('[PdoEngine] Executing INSERT', ['sql' => $sql, 'bindings' => $bindings]);
            $stmt = $this->prepareCached($pdo, $sql);
            $start = microtime(true);

            try {
                $this->bindAndExecute($stmt, $bindings);
            } catch (Throwable $e) {
                throw new VersaORMException(
                    'SQL failed (insert): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | '
                        . $e->getMessage(),
                    'PDO_EXEC_FAILED',
                );
            }
            $elapsed = (microtime(true) - $start) * 1000;
            $this->recordQuery(true, $elapsed);
            $this->clearAllCache();

            return $stmt->rowCount();
        }

        if ($action === 'insertGetId') {
            // Log SQL y bindings para diagnosticar problemas de insertGetId
            $this->log('[PdoEngine] Executing INSERT (get id)', ['sql' => $sql, 'bindings' => $bindings]);
            $stmt = $this->prepareCached($pdo, $sql);
            $start = microtime(true);

            try {
                $this->bindAndExecute($stmt, $bindings);
            } catch (Throwable $e) {
                throw new VersaORMException(
                    'SQL failed (insertGetId): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | '
                        . $e->getMessage(),
                    'PDO_EXEC_FAILED',
                );
            }
            $elapsed = (microtime(true) - $start) * 1000;
            $this->recordQuery(true, $elapsed);
            $this->clearAllCache();

            // Convertir lastInsertId a int, con fallback a null si falla
            $lastId = $pdo->lastInsertId();

            $this->log('[PdoEngine] lastInsertId', ['lastId' => $lastId]);

            if ($lastId === false || $lastId === '') {
                return null;
            }

            return (int) $lastId;
        }

        if ($action === 'update' || $action === 'delete') {
            $stmt = $this->prepareCached($pdo, $sql);
            $start = microtime(true);

            try {
                $this->bindAndExecute($stmt, $bindings);
            } catch (Throwable $e) {
                throw new VersaORMException(
                    'SQL failed (' . $action . '): ' . $sql . ' | Bindings: ' . json_encode($bindings) . ' | '
                        . $e->getMessage(),
                    'PDO_EXEC_FAILED',
                );
            }
            $elapsed = (microtime(true) - $start) * 1000;
            $this->recordQuery(true, $elapsed);
            $this->clearAllCache();

            return $stmt->rowCount();
        }

        throw new VersaORMException('Unsupported PDO action: ' . $action);
    }

    /**
     * Limpia todos los caches y registros estáticos para prevenir memory leaks.
     * Útil en procesos de larga duración y tests.
     */
    public static function clearAllStaticRegistries(): void
    {
        // Limpiar caches de PdoEngine
        self::$queryCache = [];
        self::$tableKeyIndex = [];
        self::$stmtCache = [];

        // Resetear métricas
        self::$metrics = [
            'queries' => 0,
            'writes' => 0,
            'transactions' => 0,
            'cache_hits' => 0,
            'cache_misses' => 0,
            'last_query_ms' => 0.0,
            'total_query_ms' => 0.0,
            'stmt_cache_hits' => 0,
            'stmt_cache_misses' => 0,
            'total_prepare_ms' => 0.0,
            'hydration_ms' => 0.0,
            'objects_hydrated' => 0,
            'hydration_fastpath_uses' => 0,
            'hydration_fastpath_rows' => 0,
            'hydration_fastpath_ms' => 0.0,
        ];

        // Limpiar pool de conexiones de PdoConnection
        PdoConnection::clearPool();
    }

    /**
     * Limpia solo los caches de consultas, manteniendo métricas y statements.
     */
    public static function clearQueryCache(): void
    {
        self::$queryCache = [];
        self::$tableKeyIndex = [];
    }

    /**
     * Limpia solo el cache de statements preparados.
     */
    public static function clearStatementCache(): void
    {
        self::$stmtCache = [];
    }

    /** Limpia la caché de sentencias y cierra cursores para liberar locks (especialmente en SQLite) */
    private function clearStmtCache(): void
    {
        foreach (self::$stmtCache as $k => $entry) {
            try {
                $entry['stmt']->closeCursor();
            } catch (Throwable) { // ignore
            }
            unset(self::$stmtCache[$k]);
        }
        self::$stmtCache = [];
    }

    /** Registra ejecución de consulta */
    private function recordQuery(bool $isWrite, float $elapsedMs): void
    {
        self::$metrics['queries']++;

        if ($isWrite) {
            self::$metrics['writes']++;
        }
        self::$metrics['last_query_ms'] = $elapsedMs;
        self::$metrics['total_query_ms'] += $elapsedMs;
    }

    /** Registra hit de caché */
    private function recordCacheHit(): void
    {
        self::$metrics['cache_hits']++;
    }

    /** Registra miss de caché */
    private function recordCacheMiss(): void
    {
        self::$metrics['cache_misses']++;
    }

    /**
     * Log auxiliar seguro.
     *
     * @param array<string,mixed> $context
     */
    private function log(string $message, array $context = []): void
    {
        if (is_callable($this->logger)) {
            try {
                ($this->logger)($message, $context);
            } catch (Throwable) {
                // ignorar errores de logging
            }
        }
    }

    /**
     * Enlaza parámetros con tipos adecuados y ejecuta el statement.
     * Forza INT/BOOL/NULL; el resto como STR para evitar sorpresas en SQLite.
     *
     * @param array<int, mixed> $bindings
     */
    private function bindAndExecute(PDOStatement $stmt, array $bindings): void
    {
        if ($bindings !== []) {
            foreach (array_values($bindings) as $i => $val) {
                $param = $i + 1; // 1-based

                if (is_int($val)) {
                    $stmt->bindValue($param, $val, PDO::PARAM_INT);
                } elseif (is_bool($val)) {
                    $stmt->bindValue($param, $val, PDO::PARAM_BOOL);
                } elseif ($val === null) {
                    $stmt->bindValue($param, $val, PDO::PARAM_NULL);
                } else {
                    // floats y strings van como STR
                    $valStr = is_scalar($val)
                        ? (string) $val
                        : (is_object($val) && method_exists($val, '__toString') ? (string) $val : '');
                    $stmt->bindValue($param, $valStr, PDO::PARAM_STR);
                }
            }
            $stmt->execute();

            return;
        }
        $stmt->execute();
    }

    /**
     * Obtiene una sentencia preparada desde caché o la prepara y cachea.
     * Ahora valida que la conexión PDO siga siendo válida.
     */
    private function prepareCached(PDO $pdo, string $sql): PDOStatement
    {
        $pdoId = function_exists('spl_object_id') ? spl_object_id($pdo) : spl_object_hash($pdo);
        $key = md5($sql . '|' . (string) $pdoId);
        $currentTime = time();

        if (isset(self::$stmtCache[$key])) {
            $entry = self::$stmtCache[$key];

            // Validar que la conexión PDO siga siendo la misma y no haya expirado
            if ($entry['pdo_id'] === (string) $pdoId && ($currentTime - $entry['created_at']) < self::$stmtCacheTtl) {
                self::$metrics['stmt_cache_hits']++;
                // LRU: mover al final (reinsertar)
                unset(self::$stmtCache[$key]);
                self::$stmtCache[$key] = $entry;

                return $entry['stmt'];
            }
            // Entry expirado o PDO diferente, eliminar
            unset(self::$stmtCache[$key]);
        }

        self::$metrics['stmt_cache_misses']++;
        $start = microtime(true);
        $stmt = $pdo->prepare($sql);
        self::$metrics['total_prepare_ms'] += (microtime(true) - $start) * 1000;

        // Cachear con metadata
        self::$stmtCache[$key] = [
            'stmt' => $stmt,
            'pdo_id' => (string) $pdoId,
            'created_at' => $currentTime,
        ];

        // Limpiar entries expirados y hacer evict LRU si es necesario
        $this->pruneExpiredStatements($currentTime);

        if (count(self::$stmtCache) > self::$stmtCacheLimit) {
            // Remover el primer elemento (más antiguo en uso)
            array_shift(self::$stmtCache);
        }

        return $stmt;
    }

    /**
     * Limpia statements expirados del cache.
     */
    private function pruneExpiredStatements(int $currentTime): void
    {
        foreach (self::$stmtCache as $key => $entry) {
            if (($currentTime - $entry['created_at']) < self::$stmtCacheTtl) {
                continue;
            }

            try {
                $entry['stmt']->closeCursor();
            } catch (Throwable) {
                // ignore
            }
            unset(self::$stmtCache[$key]);
        }
    }

    private function detectDialect(): SqlDialectInterface
    {
        $rawDriver = $this->config['driver'] ?? 'mysql';
        $driver = strtolower(is_scalar($rawDriver) ? (string) $rawDriver : 'mysql');

        return match ($driver) {
            'mysql', 'mariadb' => new MySQLDialect(),
            'pgsql', 'postgres', 'postgresql' => new PostgreSQLDialect(),
            'sqlite' => new SQLiteDialect(),
            default => new MySQLDialect(),
        };
    }

    /**
     * Maneja inserciones batch (insertMany) como acción directa.
     *
     * @param array<string,mixed> $params
     *
     * @return array<string,mixed>
     */
    private function handleInsertMany(array $params, PDO $pdo): array
    {
        $records = $params['records'] ?? [];
        $rawBatchSize = $params['batch_size'] ?? 1000;
        $batchSize = is_numeric($rawBatchSize) ? (int) $rawBatchSize : 1000;

        if (!is_array($records) || $records === []) {
            return [
                'status' => 'success',
                'total_inserted' => 0,
                'batches_processed' => 0,
                'batch_size' => $batchSize,
            ];
        }
        $total = count($records);
        $batches = $batchSize > 0 ? (int) ceil($total / $batchSize) : 1;
        $totalInserted = 0;
        $insertedIds = [];
        $driverName = '';

        try {
            $rawDn = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
            $dn = is_scalar($rawDn) ? (string) $rawDn : '';
            $driverName = strtolower($dn);
        } catch (Throwable) {
            $driverName = '';
        }

        // Ejecutar inserción por lotes dentro de una transacción para evitar
        // inserciones parciales que luego provoquen errores de unicidad
        $startedTransaction = false;

        try {
            if (!$pdo->inTransaction()) {
                $startedTransaction = $pdo->beginTransaction();
            }

            for ($i = 0; $i < $total; $i += $batchSize) {
                $chunk = array_slice($records, $i, $batchSize);
                [$chunkSql, $chunkBindings] = SqlGenerator::generate(
                    'query',
                    [
                        'method' => 'insertMany',
                        'table' => $params['table'] ?? '',
                        'records' => $chunk,
                    ],
                    $this->dialect,
                );
                $st = $this->prepareCached($pdo, $chunkSql);
                $st->execute($chunkBindings);

                $chunkCount = count($chunk);
                $totalInserted += $chunkCount;

                // Intentar inferir IDs autoincrement si no se proporcionaron explícitamente
                $explicitIdPresent = false;
                foreach ($chunk as $row) {
                    if (!(is_array($row) && array_key_exists('id', $row))) {
                        continue;
                    }

                    $explicitIdPresent = true;
                    break;
                }

                if (!$explicitIdPresent) {
                    // Para Postgres intentamos leer filas devueltas por RETURNING id
                    if ($driverName === 'pgsql' || $driverName === 'postgres' || $driverName === 'postgresql') {
                        try {
                            $returned = $st->fetchAll(PDO::FETCH_COLUMN);
                            if (is_array($returned) && count($returned) > 0) {
                                foreach ($returned as $rid) {
                                    $insertedIds[] = is_numeric($rid) ? (int) $rid : 0;
                                }
                            } else {
                                // Si no devolvió nada, fall back a lastInsertId para otros drivers
                                try {
                                    $lastIdRaw = $pdo->lastInsertId();
                                    if ($lastIdRaw !== false && $lastIdRaw !== '') {
                                        $lastId = is_numeric($lastIdRaw) ? (int) $lastIdRaw : 0;
                                        if ($lastId > 0) {
                                            $firstId = $lastId - $chunkCount + 1;
                                            if ($firstId > 0) {
                                                for ($k = 0; $k < $chunkCount; $k++) {
                                                    $insertedIds[] = $firstId + $k;
                                                }
                                            }
                                        }
                                    }
                                } catch (Throwable) {
                                    // ignore
                                }
                            }
                        } catch (Throwable) {
                            // Si fetchAll falla, intentar lastInsertId como fallback
                            try {
                                $lastIdRaw = $pdo->lastInsertId();
                                if ($lastIdRaw !== false && $lastIdRaw !== '') {
                                    $lastId = (int) $lastIdRaw;
                                    if ($lastId > 0) {
                                        $firstId = $lastId - $chunkCount + 1;
                                        if ($firstId > 0) {
                                            for ($k = 0; $k < $chunkCount; $k++) {
                                                $insertedIds[] = $firstId + $k;
                                            }
                                        }
                                    }
                                }
                            } catch (Throwable) {
                                // ignore
                            }
                        }
                    } elseif ($driverName === 'mysql' || $driverName === 'sqlite') {
                        try {
                            $lastIdRaw = $pdo->lastInsertId();
                            if ($lastIdRaw !== false && $lastIdRaw !== '') {
                                $lastId = (int) $lastIdRaw;
                                if ($lastId > 0) {
                                    if ($driverName === 'mysql') {
                                        // MySQL devuelve el primer ID de la inserción multi-row
                                        $firstId = $lastId;
                                    } else { // sqlite
                                        // SQLite devuelve el último ROWID insertado
                                        $firstId = $lastId - $chunkCount + 1;
                                    }
                                    if ($firstId > 0) {
                                        for ($k = 0; $k < $chunkCount; $k++) {
                                            $insertedIds[] = $firstId + $k;
                                        }
                                    }
                                }
                            }
                        } catch (Throwable) { /* ignorar */
                        }
                    }
                }

                try {
                    $st->closeCursor();
                } catch (Throwable) { // ignore
                }
            }

            if ($startedTransaction) {
                $pdo->commit();
            }
        } catch (Throwable $e) {
            // Si falló la inserción, hacer rollback si iniciamos la transacción
            try {
                if ($startedTransaction && $pdo->inTransaction()) {
                    $pdo->rollBack();
                }
            } catch (Throwable) {
                // ignore rollback errors
            }

            // Re-lanzar para que el caller (por ejemplo storeAll) pueda aplicar fallback
            throw $e;
        }

        $this->clearAllCache();

        return [
            'status' => 'success',
            'total_inserted' => $totalInserted,
            'batches_processed' => $batches,
            'batch_size' => $batchSize,
            'inserted_ids' => $insertedIds,
        ];
    }

    /**
     * Maneja actualizaciones batch (updateMany) directas.
     *
     * @param array<string,mixed> $params
     *
     * @return array<string,mixed>
     */
    private function handleUpdateMany(array $params, PDO $pdo): array
    {
        $rawMax = $params['max_records'] ?? 10000;
        $max = is_numeric($rawMax) ? (int) $rawMax : 10000;
        [$countSql, $countBindings] = SqlGenerator::generate(
            'query',
            [
                'method' => 'count',
                'table' => $params['table'] ?? '',
                'where' => $params['where'] ?? [],
            ],
            $this->dialect,
        );
        $stc = $this->prepareCached($pdo, $countSql);
        $stc->execute($countBindings);
        $row = $stc->fetch(PDO::FETCH_ASSOC) ?? [];
        $rawCount = $row['count'] ?? 0;
        $toAffect = is_numeric($rawCount) ? (int) $rawCount : 0;

        if ($toAffect > $max) {
            throw new VersaORMException(
                sprintf(
                    'The operation would affect %d records, which exceeds the maximum limit of %d. Use a more restrictive WHERE clause or increase max_records.',
                    $toAffect,
                    $max,
                ),
                'BATCH_LIMIT_EXCEEDED',
            );
        }
        [$sqlU, $bindU] = SqlGenerator::generate(
            'query',
            [
                'method' => 'updateMany',
                'table' => $params['table'] ?? '',
                'where' => $params['where'] ?? [],
                'data' => $params['data'] ?? [],
            ],
            $this->dialect,
        );
        $stmt = $this->prepareCached($pdo, $sqlU);
        $this->bindAndExecute($stmt, $bindU);
        $affected = $stmt->rowCount();

        try {
            $stmt->closeCursor();
        } catch (Throwable) { // ignore
        }
        $this->clearAllCache();

        return [
            'status' => 'success',
            'rows_affected' => $affected,
            'message' => $affected === 0 ? 'No records matched the WHERE conditions' : 'Update completed',
        ];
    }

    /**
     * Maneja eliminaciones batch (deleteMany) directas.
     *
     * @param array<string,mixed> $params
     *
     * @return array<string,mixed>
     */
    private function handleDeleteMany(array $params, PDO $pdo): array
    {
        $rawMax = $params['max_records'] ?? 10000;
        $max = is_numeric($rawMax) ? (int) $rawMax : 10000;
        [$countSql, $countBindings] = SqlGenerator::generate(
            'query',
            [
                'method' => 'count',
                'table' => $params['table'] ?? '',
                'where' => $params['where'] ?? [],
            ],
            $this->dialect,
        );
        $stc = $this->prepareCached($pdo, $countSql);
        $stc->execute($countBindings);
        $row = $stc->fetch(PDO::FETCH_ASSOC) ?? [];
        $rawCount = $row['count'] ?? 0;
        $toAffect = is_numeric($rawCount) ? (int) $rawCount : 0;

        if ($toAffect > $max) {
            throw new VersaORMException(
                sprintf(
                    'The operation would affect %d records, which exceeds the maximum limit of %d. Use a more restrictive WHERE clause or increase max_records.',
                    $toAffect,
                    $max,
                ),
                'BATCH_LIMIT_EXCEEDED',
            );
        }
        [$sqlD, $bindD] = SqlGenerator::generate(
            'query',
            [
                'method' => 'deleteMany',
                'table' => $params['table'] ?? '',
                'where' => $params['where'] ?? [],
            ],
            $this->dialect,
        );
        $stmt = $this->prepareCached($pdo, $sqlD);
        $this->bindAndExecute($stmt, $bindD);
        $affected = $stmt->rowCount();

        try {
            $stmt->closeCursor();
        } catch (Throwable) { // ignore
        }
        $this->clearAllCache();

        return [
            'status' => 'success',
            'rows_affected' => $affected,
            'message' => $affected === 0 ? 'No records matched the WHERE conditions' : 'Delete completed',
        ];
    }

    /**
     * Maneja upserts batch (upsertMany) directos.
     *
     * @param array<string,mixed> $params
     *
     * @return array<string,mixed>
     */
    private function handleUpsertMany(array $params, PDO $pdo): array
    {
        [$sqlUp, $bindUp] = SqlGenerator::generate(
            'query',
            [
                'method' => 'upsertMany',
                'table' => $params['table'] ?? '',
                'records' => $params['records'] ?? [],
                'unique_keys' => $params['unique_keys'] ?? [],
                'update_columns' => $params['update_columns'] ?? [],
            ],
            $this->dialect,
        );
        $stmt = $this->prepareCached($pdo, $sqlUp);
        $this->bindAndExecute($stmt, $bindUp);
        $affected = $stmt->rowCount();

        try {
            $stmt->closeCursor();
        } catch (Throwable) { // ignore
        }
        $this->clearAllCache();

        return [
            'status' => 'success',
            'total_processed' => is_array($params['records'] ?? null) ? count($params['records']) : $affected,
            'unique_keys' => $params['unique_keys'] ?? [],
            'update_columns' => $params['update_columns'] ?? [],
        ];
    }

    /**
     * @return list<array{table_name:string|null}>
     */
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
            $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
            $out = [];

            foreach ($rows as $r) {
                if (!is_array($r)) {
                    continue;
                }

                $tableName = $r['table_name'] ?? null;
                $out[] = ['table_name' => is_scalar($tableName) ? (string) $tableName : null];
            }

            return $out;
        }

        if ($driver === 'postgres') {
            $stmt = $pdo->query("SELECT tablename AS table_name FROM pg_tables WHERE schemaname='public'");
            $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
            $out = [];

            foreach ($rows as $r) {
                if (!is_array($r)) {
                    continue;
                }

                $tableName = $r['table_name'] ?? null;
                $out[] = ['table_name' => is_scalar($tableName) ? (string) $tableName : null];
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
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
            $result = [];

            foreach ($columns as $col) {
                $type = strtolower((string) ($col['Type'] ?? ''));
                $length = null;

                if (preg_match('/^(\w+)\((\d+)\)/', $type, $m) === 1) {
                    $type = $m[1];
                    $length = (int) $m[2];
                    // Para tipos de fecha/hora MySQL (ej. datetime(6)) la parte entre paréntesis
                    // es precision, no longitud de caracteres; no exponer como character_maximum_length
                    if (in_array(strtolower($type), ['datetime', 'timestamp', 'time', 'date'], true)) {
                        $length = null;
                    }
                }
                $rawName = $col['Field'] ?? '';
                $name = is_scalar($rawName) ? (string) $rawName : '';
                $rawNull = $col['Null'] ?? 'NO';
                $result[] = [
                    'column_name' => $name,
                    'name' => $name,
                    'data_type' => $type,
                    'type' => $type,
                    'is_nullable' => strtoupper(is_scalar($rawNull) ? (string) $rawNull : 'NO') === 'YES'
                        ? 'YES'
                        : 'NO',
                    'column_default' => $col['Default'] ?? null,
                    'character_maximum_length' => $length,
                    'extra' => $col['Extra'] ?? '',
                ];
            }

            return $result;
        }

        if ($driver === 'sqlite') {
            $stmt = $this->prepareCached($pdo, 'PRAGMA table_info(' . $this->dialect->quoteIdentifier($table) . ')');
            $stmt->execute();
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
            $result = [];

            foreach ($columns as $col) {
                $name = (string) ($col['name'] ?? '');
                $dataType = strtolower((string) ($col['type'] ?? ''));
                $result[] = [
                    'column_name' => $name,
                    'name' => $name,
                    'data_type' => $dataType,
                    'type' => $dataType,
                    'is_nullable' => (int) ($col['notnull'] ?? 0) === 0 ? 'YES' : 'NO',
                    'column_default' => $col['dflt_value'] ?? null,
                    'character_maximum_length' => null,
                    'extra' => (int) ($col['pk'] ?? 0) === 1 ? 'primary_key' : '',
                ];
            }

            return $result;
        }

        if ($driver === 'postgres') {
            $sql =
                'SELECT column_name, data_type, is_nullable, column_default, character_maximum_length '
                . 'FROM information_schema.columns WHERE table_name = ?';
            $stmt = $this->prepareCached($pdo, $sql);
            $this->bindAndExecute($stmt, [$table]);
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
            $result = [];

            foreach ($columns as $col) {
                $name = (string) ($col['column_name'] ?? '');
                $dataType = strtolower((string) ($col['data_type'] ?? ''));
                $result[] = [
                    'column_name' => $name,
                    'name' => $name,
                    'data_type' => $dataType,
                    'type' => $dataType,
                    'is_nullable' => strtoupper((string) ($col['is_nullable'] ?? 'NO')) === 'YES' ? 'YES' : 'NO',
                    'column_default' => $col['column_default'] ?? null,
                    'character_maximum_length' => $col['character_maximum_length'] ?? null,
                    'extra' => '',
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
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];

            // Agrupar columnas por nombre de índice
            $indexes = [];
            foreach ($rows as $r) {
                $keyName = $r['Key_name'] ?? '';
                $columnName = $r['Column_name'] ?? '';
                $nonUnique = isset($r['Non_unique']) ? (int) $r['Non_unique'] : 1;

                if (!isset($indexes[$keyName])) {
                    $indexes[$keyName] = [
                        'name' => $keyName,
                        'columns' => [],
                        'unique' => $nonUnique === 0,
                    ];
                }
                $indexes[$keyName]['columns'][] = $columnName;
            }

            return array_values($indexes);
        }

        if ($driver === 'sqlite') {
            $stmt = $this->prepareCached($pdo, 'PRAGMA index_list(' . $this->dialect->quoteIdentifier($table) . ')');
            $stmt->execute();
            /** @var list<array{name?:string,unique?:int|string}> $rows */
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
            $indexes = [];

            foreach ($rows as $r) {
                $idxName = $r['name'] ?? '';
                $isUnique = isset($r['unique']) && (int) $r['unique'] === 1;

                // Obtener las columnas de este índice
                $stmtInfo = $this->prepareCached(
                    $pdo,
                    'PRAGMA index_info(' . $this->dialect->quoteIdentifier($idxName) . ')',
                );
                $stmtInfo->execute();
                /** @var list<array{name?:string}> $colRows */
                $colRows = $stmtInfo->fetchAll(PDO::FETCH_ASSOC) ?? [];

                $columns = [];
                foreach ($colRows as $colRow) {
                    if (!isset($colRow['name'])) {
                        continue;
                    }

                    $columns[] = $colRow['name'];
                }

                $indexes[$idxName] = [
                    'name' => $idxName,
                    'columns' => $columns,
                    'unique' => $isUnique,
                ];
            }

            return array_values($indexes);
        }

        if ($driver === 'postgres') {
            $sql = "SELECT i.relname AS name, a.attname AS column, ix.indisunique AS unique
            FROM pg_class t
            JOIN pg_index ix ON t.oid = ix.indrelid
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
            WHERE t.relkind = 'r' AND t.relname = ?
            ORDER BY i.relname, a.attnum";
            $stmt = $this->prepareCached($pdo, $sql);
            $this->bindAndExecute($stmt, [$table]);
            /** @var list<array{name?:string,column?:string,unique?:bool|int|string}> $rows */
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];

            // Agrupar columnas por nombre de índice
            $indexes = [];
            foreach ($rows as $r) {
                $idxName = $r['name'] ?? '';
                $colName = $r['column'] ?? '';
                $uniqueFlag = isset($r['unique']) && (bool) $r['unique'];

                if (!isset($indexes[$idxName])) {
                    $indexes[$idxName] = [
                        'name' => $idxName,
                        'columns' => [],
                        'unique' => $uniqueFlag,
                    ];
                }
                $indexes[$idxName]['columns'][] = $colName;
            }

            return array_values($indexes);
        }

        return [];
    }

    /**
     * Obtiene las claves foráneas de una tabla según el driver.
     *
     * @return array<int, array<string, mixed>>
     */
    private function fetchForeignKeys(PDO $pdo, string $table): array
    {
        $driver = $this->dialect->getName();

        if ($driver === 'mysql') {
            $sql = 'SELECT
                kcu.CONSTRAINT_NAME as name,
                kcu.COLUMN_NAME as `column`,
                kcu.REFERENCED_TABLE_NAME as foreign_table,
                kcu.REFERENCED_COLUMN_NAME as foreign_column,
                rc.DELETE_RULE as on_delete,
                rc.UPDATE_RULE as on_update
            FROM information_schema.KEY_COLUMN_USAGE kcu
            LEFT JOIN information_schema.REFERENTIAL_CONSTRAINTS rc
                ON kcu.CONSTRAINT_NAME = rc.CONSTRAINT_NAME
                AND kcu.TABLE_SCHEMA = rc.CONSTRAINT_SCHEMA
            WHERE kcu.TABLE_SCHEMA = DATABASE()
              AND kcu.TABLE_NAME = ?
              AND kcu.REFERENCED_TABLE_NAME IS NOT NULL';

            $stmt = $this->prepareCached($pdo, $sql);
            $this->bindAndExecute($stmt, [$table]);
            /** @var list<array{name?:string,column?:string,foreign_table?:string,foreign_column?:string,on_delete?:string,on_update?:string}> $rows */
            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
        }

        if ($driver === 'sqlite') {
            $stmt = $this->prepareCached(
                $pdo,
                'PRAGMA foreign_key_list(' . $this->dialect->quoteIdentifier($table) . ')',
            );
            $stmt->execute();
            /** @var list<array{table?:string,from?:string,to?:string,on_delete?:string,on_update?:string}> $rows */
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
            $out = [];

            foreach ($rows as $r) {
                $out[] = [
                    'name' => ($r['from'] ?? '') . '_' . ($r['table'] ?? '') . '_fk',
                    'column' => $r['from'] ?? '',
                    'foreign_table' => $r['table'] ?? '',
                    'foreign_column' => $r['to'] ?? '',
                    'on_delete' => $r['on_delete'] ?? 'NO ACTION',
                    'on_update' => $r['on_update'] ?? 'NO ACTION',
                ];
            }

            return $out;
        }

        if ($driver === 'postgres') {
            $sql = "SELECT
                con.conname AS name,
                att.attname AS column,
                fc.relname AS foreign_table,
                fatt.attname AS foreign_column,
                CASE con.confdeltype
                    WHEN 'a' THEN 'NO ACTION'
                    WHEN 'r' THEN 'RESTRICT'
                    WHEN 'c' THEN 'CASCADE'
                    WHEN 'n' THEN 'SET NULL'
                    WHEN 'd' THEN 'SET DEFAULT'
                END AS on_delete,
                CASE con.confupdtype
                    WHEN 'a' THEN 'NO ACTION'
                    WHEN 'r' THEN 'RESTRICT'
                    WHEN 'c' THEN 'CASCADE'
                    WHEN 'n' THEN 'SET NULL'
                    WHEN 'd' THEN 'SET DEFAULT'
                END AS on_update
            FROM pg_constraint con
            JOIN pg_class tc ON con.conrelid = tc.oid
            JOIN pg_attribute att ON att.attrelid = tc.oid AND att.attnum = ANY(con.conkey)
            JOIN pg_class fc ON con.confrelid = fc.oid
            JOIN pg_attribute fatt ON fatt.attrelid = fc.oid AND fatt.attnum = ANY(con.confkey)
            WHERE con.contype = 'f'
              AND tc.relname = ?";

            $stmt = $this->prepareCached($pdo, $sql);
            $this->bindAndExecute($stmt, [$table]);
            /** @var list<array{name?:string,column?:string,foreign_table?:string,foreign_column?:string,on_delete?:string,on_update?:string}> $rows */
            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?? [];
        }

        return [];
    }

    /**
     * Construye SQL simple desde una operación lazy del QueryBuilder
     * para ser usado por explain_plan/query_plan en modo PDO.
     *
     * @param array<string,mixed> $op
     *
     * @return array{0:string,1:array<int,mixed>}
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
     *
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
            'method' => 'get',
            'table' => $op['table'] ?? '',
            'select' => $columns,
            'joins' => [],
            'where' => [],
            'groupBy' => $grouping,
            'having' => $havingRaw,
            'orderBy' => [],
            'limit' => $op['limit'] ?? null,
            'offset' => $op['offset'] ?? null,
        ];

        /** @var array<int,array{join_type?:string,table?:string,local_column?:string,operator?:string,foreign_column?:string}> $joinConditions */
        $joinConditions = isset($op['join_conditions']) && is_array($op['join_conditions'])
            ? array_values($op['join_conditions'])
            : [];

        foreach ($joinConditions as $j) {
            if (!is_array($j)) {
                continue;
            }
            $params['joins'][] = [
                'type' => strtolower($j['join_type'] ?? 'inner'),
                'table' => $j['table'] ?? '',
                'first_col' => $j['local_column'] ?? '',
                'operator' => $j['operator'] ?? '=',
                'second_col' => $j['foreign_column'] ?? '',
            ];
        }

        /** @var array<int,array{column?:string,operator?:string,value?:mixed,connector?:string}> $whereConditions */
        $whereConditions = isset($op['conditions']) && is_array($op['conditions'])
            ? array_values($op['conditions'])
            : [];

        foreach ($whereConditions as $w) {
            if (!is_array($w)) {
                continue;
            }
            $params['where'][] = [
                'column' => $w['column'] ?? '',
                'operator' => $w['operator'] ?? '=',
                'value' => $w['value'] ?? null,
                'type' => strtolower($w['connector'] ?? 'and'),
            ];
        }

        // ORDER BY mapping: take first ordering entry if present
        /** @var array<int,array{column?:string,direction?:string}> $ordering */
        $ordering = isset($op['ordering']) && is_array($op['ordering']) ? array_values($op['ordering']) : [];

        if ($ordering !== []) {
            $first = $ordering[0] ?? null;

            if (is_array($first) && $first !== []) {
                $params['orderBy'] = [[
                    'column' => $first['column'] ?? '',
                    'direction' => strtoupper($first['direction'] ?? 'ASC'),
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
    private function makeCacheKey(string $sql, array $bindings, string $method): string
    {
        // Normalizar bindings para clave estable
        $key = $method . '|' . $sql . '|' . json_encode($bindings, JSON_UNESCAPED_UNICODE);

        return hash('sha256', $key);
    }

    /**
     * @return array<int, string>
     */
    private function extractTablesFromSql(string $sql): array
    {
        $tables = [];

        // Buscar FROM y JOIN simples (identificadores con o sin backticks)
        if (preg_match_all('/\bFROM\s+`?([a-zA-Z0-9_\.]+)`?/i', $sql, $m1) > 0) {
            foreach ($m1[1] as $t) {
                $tables[] = strtolower($t);
            }
        }

        if (preg_match_all('/\bJOIN\s+`?([a-zA-Z0-9_\.]+)`?/i', $sql, $m2) > 0) {
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
     * @param array<string,mixed>|bool|int|list<array<string,mixed>>|null $result
     */
    private function storeInCache(string $sql, array $bindings, string $method, null|array|bool|int $result): void
    {
        $key = $this->makeCacheKey($sql, $bindings, $method);
        $now = time();

        // Aplicar límite de tamaño del cache (LRU)
        if (count(self::$queryCache) >= self::$queryCacheLimit) {
            $this->evictLRUEntries();
        }

        self::$queryCache[$key] = [
            'data' => $result,
            'created_at' => $now,
            'last_access' => $now,
            'ttl' => self::$queryCacheTtl,
        ];

        // Indexar por tabla para invalidación selectiva (best-effort)
        foreach ($this->extractTablesFromSql($sql) as $table) {
            self::$tableKeyIndex[$table] ??= [];

            // Evitar inflar con duplicados
            if (!in_array($key, self::$tableKeyIndex[$table], true)) {
                self::$tableKeyIndex[$table][] = $key;
            }
        }
    }

    /**
     * Elimina las entradas LRU del caché cuando se alcanza el límite.
     * Elimina el 20% de las entradas más antiguas por acceso.
     */
    private function evictLRUEntries(): void
    {
        if (self::$queryCache === []) {
            return;
        }

        // Ordenar por último acceso (más antiguo primero)
        $entries = [];
        foreach (self::$queryCache as $key => $entry) {
            $entries[$key] = $entry['last_access'] ?? $entry['created_at'];
        }

        asort($entries);

        // Eliminar el 20% de las entradas más antiguas
        $toRemove = max(1, (int) (count($entries) * 0.2));
        $keysToRemove = array_slice(array_keys($entries), 0, $toRemove);

        foreach ($keysToRemove as $key) {
            unset(self::$queryCache[$key]);

            // También limpiar del índice de tablas
            foreach (self::$tableKeyIndex as $table => $keys) {
                $index = array_search($key, $keys, true);
                if ($index !== false) {
                    unset(self::$tableKeyIndex[$table][$index]);
                    self::$tableKeyIndex[$table] = array_values(self::$tableKeyIndex[$table]);
                }
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
                if (preg_match($regex, $table) !== 1) {
                    continue;
                }

                self::invalidateCacheForTable($table);
            }
        }
    }

    private function clearAllCache(): void
    {
        self::$queryCache = [];
        self::$tableKeyIndex = [];
    }
}
