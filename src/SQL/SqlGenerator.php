<?php

declare(strict_types=1);

namespace VersaORM\SQL;

use VersaORM\VersaORMException;

use function count;
use function in_array;
use function is_array;
use function is_string;

class SqlGenerator
{
    /**
     * Generate SQL and bindings based on action + params from QueryBuilder payload.
     * Returns array [sql, bindings].
     */
    /**
     * @param array<string, mixed> $params
     *
     * @return array{0:string,1:array<int, mixed>}
     */
    public static function generate(string $action, array $params, SqlDialectInterface $dialect): array
    {
        if ($action === 'raw') {
            $sql = (string) ($params['query'] ?? '');
            /** @var array<int,mixed> $bindings */
            $bindings = [];

            if (isset($params['bindings']) && is_array($params['bindings'])) {
                // forzamos índices numéricos consecutivos
                $bindings = array_values($params['bindings']);
            }

            return [$sql, $bindings]; // tuple exacta
        }

        if ($action === 'query') {
            $method = (string) ($params['method'] ?? 'get');

            // Batch/write methods mapped into query by QueryBuilder
            if (in_array($method, ['insertMany', 'updateMany', 'deleteMany', 'upsertMany'], true)) {
                // Defer to specific compilers that return [sql, bindings] possibly for one batch
                return self::compileBatch($method, $params, $dialect);
            }

            return self::compileSelect($method, $params, $dialect);
        }

        if (in_array($action, ['insert', 'insertGetId'], true)) {
            return self::compileInsert($params, $dialect);
        }

        if ($action === 'update') {
            return self::compileUpdate($params, $dialect);
        }

        if ($action === 'delete') {
            return self::compileDelete($params, $dialect);
        }

        throw new VersaORMException('PDO engine does not support this action yet: ' . $action);
    }

    /**
     * Compila SELECT soportando métodos get|first|count|exists.
     *
     * @param array<string, mixed> $params Forma esperada (parcial):
     *                                     table: string,
     *                                     select?: list<string|array{type:string,expression?:string,subquery?:string}>,
     *                                     joins?: list<array{type?:string,table?:string,first_col?:string,second_col?:string,operator?:string,subquery?:string,alias?:string,subquery_bindings?:array<int,mixed>}>,
     *                                     where?: list<array{type?:string,operator?:string,column?:string,first_col?:string,second_col?:string,value:mixed}>,
     *                                     groupBy?: list<string>|array{type:string,expression?:string,bindings?:array<int,mixed>},
     *                                     having?: list<array{column:string,operator?:string,value:mixed}>,
     *                                     orderBy?: list<array{column?:string,direction?:string,type?:string,expression?:string}>,
     *                                     limit?: int, offset?: int
     *
     * @return array{0:string,1:array<int, mixed>}
     */
    private static function compileSelect(string $method, array $params, SqlDialectInterface $dialect): array
    {
        $table = (string) ($params['table'] ?? '');
        /**
         * from_sub soporte: ['sql'=>string,'alias'=>string,'bindings'=>list<mixed>]
         * Si se provee, sustituye la referencia de FROM por (sql) alias y antepone sus bindings.
         * 'table' sigue siendo requerido internamente (para compatibilidad) pero puede ser placeholder.
         */
        $fromSub = null;

        if (isset($params['from_sub']) && is_array($params['from_sub']) && isset($params['from_sub']['sql'], $params['from_sub']['alias'])) {
            $fromSub = [
                'sql' => (string) $params['from_sub']['sql'],
                'alias' => (string) $params['from_sub']['alias'],
                'bindings' => is_array($params['from_sub']['bindings'] ?? null) ? array_values($params['from_sub']['bindings']) : [],
            ];
        }

        if ($table === '' && $fromSub === null) {
            throw new VersaORMException('Missing table for SELECT');
        }
        /**
         * Normalizamos SELECT asegurando lista tipada.
         *
         * @var list<array{type:string,expression?:string,subquery?:string}|string> $select
         */
        $select = [];

        if (isset($params['select']) && is_array($params['select'])) {
            $selectRaw = array_values($params['select']);

            foreach ($selectRaw as $s) {
                /** @var mixed $s */
                if (is_string($s)) {
                    $select[] = $s;
                    continue;
                }

                if (is_array($s) && isset($s['type']) && is_string($s['type'])) {
                    $select[] = [
                        'type' => $s['type'],
                        'expression' => isset($s['expression']) && is_string($s['expression']) ? $s['expression'] : null,
                        'subquery' => isset($s['subquery']) && is_string($s['subquery']) ? $s['subquery'] : null,
                    ];
                }
            }
        }

        if ($select === []) {
            $select = ['*'];
        }
        /** @var list<string> $selectSqlParts */
        $selectSqlParts = [];

        foreach ($select as $sel) {
            /** @var array{type:string,expression?:string,subquery?:string}|string $sel */
            if (is_string($sel)) {
                $selectSqlParts[] = self::compileSelectPart($sel, $dialect);
                continue;
            }
            $type = (string) ($sel['type'] ?? '');

            if ($type === 'raw' && isset($sel['expression'])) {
                $selectSqlParts[] = $sel['expression'];
            } elseif ($type === 'subquery') {
                throw new VersaORMException('Subquery SELECT not supported yet in PDO engine');
            }
        }

        if (empty($selectSqlParts)) {
            $selectSqlParts[] = '*';
        }

        // FROM base o derivado
        if ($fromSub !== null) {
            // Envolver todo el UNION en un único paréntesis
            $sql = 'SELECT ' . implode(', ', $selectSqlParts) . ' FROM (' . $fromSub['sql'] . ') AS ' . $dialect->quoteIdentifier($fromSub['alias']);
        } else {
            $sql = 'SELECT ' . implode(', ', $selectSqlParts) . ' FROM ' . self::compileTableReference($table, $dialect);
        }
        /** @var array<int,mixed> $bindings */
        $bindings = [];

        if ($fromSub !== null) {
            $bindings = array_merge($bindings, $fromSub['bindings']);
        }

        // Debug logging para diagnosticar errores de sintaxis en subconsultas UNION derivadas.
        // Controlado por variable de entorno VERSA_DEBUG_SQL=1 para evitar ruido en entornos productivos.
        if ($fromSub !== null && \function_exists('error_log') && getenv('VERSA_DEBUG_SQL') === '1') {
            error_log('[DEBUG][SqlGenerator] from_sub SQL: ' . $sql . ' | bindings=' . json_encode($bindings));

            try {
                $logDir = __DIR__ . '/../../logs';
                if (!is_dir($logDir)) {
                    @mkdir($logDir, 0777, true);
                }
                @file_put_contents($logDir . '/sql_debug.log', '[' . date('H:i:s') . '] ' . $sql . ' | bindings=' . json_encode($bindings) . "\n", FILE_APPEND);
            } catch (\Throwable $e) {
                // Ignorar errores de logging
            }
        }

        // JOINS (inner, left, right, cross, joinSub); FULL OUTER (limitado)
        /** @var list<array{type?:string,table?:string,first_col?:string,second_col?:string,operator?:string,subquery?:string,alias?:string,subquery_bindings?:array<int,mixed>}> $joins */
        $joins = [];

        if (isset($params['joins']) && is_array($params['joins'])) {
            $joinsRaw = array_values($params['joins']);

            foreach ($joinsRaw as $j) {
                if (!is_array($j)) {
                    continue;
                }
                $joins[] = $j; // shape se describe en docblock
            }
        }
        // Manejo especial para FULL OUTER JOIN cuando es un único join simple
        $hasFullOuter = count($joins) === 1 && (strtolower((string) ($joins[0]['type'] ?? '')) === 'full_outer');

        if ($hasFullOuter) {
            // Emular con UNION de LEFT y RIGHT JOIN
            $j = $joins[0];
            $baseFrom = ' FROM ' . self::compileTableReference($table, $dialect);
            $onClause = self::compileJoinColumn((string) $j['first_col'], $dialect)
                . ' ' . ($j['operator'] ?? '=') . ' '
                . self::compileJoinColumn((string) $j['second_col'], $dialect);
            $sel = implode(', ', $selectSqlParts);
            $leftSql = 'SELECT ' . $sel . $baseFrom . ' LEFT JOIN ' . self::compileTableReference((string) $j['table'], $dialect)
                . ' ON ' . $onClause;
            $rightSql = 'SELECT ' . $sel . $baseFrom . ' RIGHT JOIN ' . self::compileTableReference((string) $j['table'], $dialect)
                . ' ON ' . $onClause;
            $sql = $leftSql . ' UNION ' . $rightSql;

            // No soportamos WHERE/GROUP/HAVING/ORDER/LIMIT en esta emulación mínima
            return [$sql, $bindings];
        }

        foreach ($joins as $join) {
            $type = strtolower((string) ($join['type'] ?? 'inner'));

            if ($type === 'cross') {
                $sql .= ' CROSS JOIN ' . self::compileTableReference((string) $join['table'], $dialect);
                continue;
            }

            if (!in_array($type, ['inner', 'left', 'right'], true)) {
                throw new VersaORMException('Join type not supported in PDO engine: ' . $type);
            }
            // joinSub support: if subquery is provided, wrap as (subquery) AS alias
            $tableRef = '';

            if (isset($join['subquery']) && is_string($join['subquery'])) {
                $alias = (string) ($join['alias'] ?? $join['table'] ?? 'subq');
                $tableRef = '(' . $join['subquery'] . ') AS ' . $dialect->quoteIdentifier($alias);

                // merge bindings from subquery
                if (isset($join['subquery_bindings']) && is_array($join['subquery_bindings'])) {
                    $bindings = array_merge($bindings, $join['subquery_bindings']);
                }
            } else {
                $tableRef = self::compileTableReference((string) $join['table'], $dialect);
            }

            $jt = strtoupper($type) . ' JOIN ' . $tableRef;
            // Soporte de condiciones múltiples
            $conditions = [];

            if (isset($join['conditions']) && is_array($join['conditions'])) {
                foreach ($join['conditions'] as $idx => $c) {
                    if (!is_array($c)) {
                        continue;
                    }
                    // Condición RAW soporta 'type' => 'raw', 'sql' y 'bindings'
                    $isRaw = isset($c['type']) && $c['type'] === 'raw' && isset($c['sql']);
                    if ($isRaw) {
                        $rawSql = (string) $c['sql'];
                        if ($rawSql === '') {
                            continue;
                        }
                        $fragment = $rawSql;
                        if ($idx > 0) {
                            $bool = strtoupper((string) ($c['boolean'] ?? 'AND')) === 'OR' ? 'OR' : 'AND';
                            $fragment = $bool . ' ' . $fragment;
                        }
                        // Acumular bindings de la condición raw
                        if (isset($c['bindings']) && is_array($c['bindings'])) {
                            $bindings = array_merge($bindings, array_values($c['bindings']));
                        }
                        $conditions[] = $fragment;
                        continue;
                    }
                    $loc = (string) ($c['local'] ?? '');
                    $opr = (string) ($c['operator'] ?? '=');
                    $for = (string) ($c['foreign'] ?? '');
                    if ($loc === '' || $for === '') {
                        continue;
                    }
                    $fragment = self::compileJoinColumn($loc, $dialect) . ' ' . $opr . ' ' . self::compileJoinColumn($for, $dialect);
                    if ($idx > 0) {
                        $bool = strtoupper((string) ($c['boolean'] ?? 'AND')) === 'OR' ? 'OR' : 'AND';
                        $fragment = $bool . ' ' . $fragment;
                    }
                    $conditions[] = $fragment;
                }
            }

            if ($conditions === []) {
                // Fallback a first_col/operator/second_col
                $first = (string) ($join['first_col'] ?? '');
                $op = (string) ($join['operator'] ?? '=');
                $second = (string) ($join['second_col'] ?? '');

                if ($first === '' || $second === '') {
                    throw new VersaORMException('Invalid JOIN columns');
                }
                $conditions[] = self::compileJoinColumn($first, $dialect) . ' ' . $op . ' ' . self::compileJoinColumn($second, $dialect);
            }
            $sql .= ' ' . $jt . ' ON ' . implode(' ', $conditions);
        }

        // WHERE
        /** @var list<array{type?:string,operator?:string,column?:string,value:mixed}> $whereList */
        $whereList = [];

        if (isset($params['where']) && is_array($params['where'])) {
            $whereRaw = array_values($params['where']);

            foreach ($whereRaw as $w) {
                if (is_array($w)) {
                    $whereList[] = $w;
                }
            }
        }
        [$whereSql, $whereBindings] = self::compileWhere($whereList, $dialect);

        if ($whereSql !== '') {
            $sql .= ' WHERE ' . $whereSql;
            $bindings = array_merge($bindings, $whereBindings);
        }

        // GROUP BY
        /** @var array{type:string,expression?:string,bindings?:array<int,mixed>}|list<string> $groupBy */
        $groupBy = $params['groupBy'] ?? [];

        if ($groupBy !== []) {
            if (is_array($groupBy) && isset($groupBy['type']) && $groupBy['type'] === 'raw') {
                $expr = isset($groupBy['expression']) ? (string) $groupBy['expression'] : '';

                if ($expr !== '') {
                    $sql .= ' GROUP BY ' . $expr;
                }

                if (isset($groupBy['bindings']) && is_array($groupBy['bindings'])) {
                    /** @var array<int,mixed> $gbB */
                    $gbB = array_values($groupBy['bindings']);
                    $bindings = array_merge($bindings, $gbB);
                }
            } elseif (is_array($groupBy)) {
                $gb = [];

                foreach ($groupBy as $col) {
                    if (is_string($col) && $col !== '') {
                        $gb[] = self::compileSelectPart($col, $dialect);
                    }
                }

                if ($gb !== []) {
                    $sql .= ' GROUP BY ' . implode(', ', $gb);
                }
            }
        }

        // HAVING (simple col op ? )
        /** @var list<array{column:string,operator?:string,value:mixed}> $having */
        $having = [];

        if (isset($params['having']) && is_array($params['having'])) {
            $havingRaw = array_values($params['having']);

            foreach ($havingRaw as $h) {
                if (is_array($h) && isset($h['column']) && is_string($h['column'])) {
                    $having[] = $h;
                }
            }
        }

        if ($having !== []) {
            /** @var list<array{0:string,1:string}> $havingParts */
            $havingParts = [];

            foreach ($having as $h) {
                $col = (string) ($h['column'] ?? '');
                $op = (string) ($h['operator'] ?? '=');
                $havingParts[] = [$col, self::compileSelectPart($col, $dialect) . ' ' . $op . ' ?'];
                $bindings[] = $h['value'] ?? null;
            }
            $sql .= ' HAVING ' . implode(' AND ', array_map(static fn ($hp): string => $hp[1], $havingParts));
        }

        // ORDER BY (single or raw)
        /** @var list<array{column?:string,direction?:string,type?:string,expression?:string}> $orderBy */
        $orderBy = [];

        if (isset($params['orderBy']) && is_array($params['orderBy'])) {
            $orderRaw = array_values($params['orderBy']);

            foreach ($orderRaw as $o) {
                if (is_array($o)) {
                    $orderBy[] = $o;
                }
            }
        }

        if ($orderBy !== []) {
            $ob = $orderBy[0] ?? [];

            if (isset($ob['type']) && $ob['type'] === 'raw') {
                $sql .= ' ORDER BY ' . ($ob['expression'] ?? '');
            } elseif (isset($ob['column'])) {
                $dir = strtoupper((string) ($ob['direction'] ?? 'ASC'));

                if (!in_array($dir, ['ASC', 'DESC'], true)) {
                    $dir = 'ASC';
                }
                $sql .= ' ORDER BY ' . self::compileSelectPart((string) $ob['column'], $dialect) . ' ' . $dir;
            }
        }

        // LIMIT/OFFSET
        $sql .= $dialect->compileLimitOffset(
            isset($params['limit']) ? (int) $params['limit'] : null,
            isset($params['offset']) ? (int) $params['offset'] : null,
        );

        if ($method === 'count') {
            // Wrap as COUNT(*) OVER subquery
            $countSql = 'SELECT COUNT(*) as count FROM (' . $sql . ') as subq';

            return [$countSql, array_values($bindings)];
        }

        if ($method === 'exists') {
            $existsSql = 'SELECT EXISTS(' . $sql . ') as exists_flag';

            return [$existsSql, array_values($bindings)];
        }

        if ($method === 'first') {
            // force single row
            $sqlFirst = $sql . ' ' . $dialect->compileLimitOffset(1, null);

            return [$sqlFirst, array_values($bindings)];
        }

        // default get
        return [$sql, array_values($bindings)];
    }

    /**
     * @param array<string, mixed> $params
     *
     * @return array{0:string,1:array<int, mixed>}
     */
    private static function compileInsert(array $params, SqlDialectInterface $dialect): array
    {
        $table = (string) ($params['table'] ?? '');
        $data = $params['data'] ?? [];

        if ($table === '' || !is_array($data) || $data === []) {
            throw new VersaORMException('Invalid INSERT parameters');
        }
        $cols = array_keys($data);
        $placeholders = array_fill(0, count($cols), '?');
        $sql = 'INSERT INTO ' . $dialect->quoteIdentifier($table)
            . ' (' . implode(', ', array_map([$dialect, 'quoteIdentifier'], $cols)) . ')'
            . ' VALUES (' . implode(', ', $placeholders) . ')';
        $bindings = array_values($data);

        return [$sql, $bindings];
    }

    /**
     * @param array<string, mixed> $params
     *
     * @return array{0:string,1:array<int, mixed>}
     */
    private static function compileUpdate(array $params, SqlDialectInterface $dialect): array
    {
        $table = (string) ($params['table'] ?? '');
        $data = $params['data'] ?? [];

        if ($table === '' || !is_array($data) || $data === []) {
            throw new VersaORMException('Invalid UPDATE parameters');
        }
        $setParts = [];
        $bindings = [];

        /** @var array<string,mixed> $data */
        foreach ($data as $col => $val) {
            $setParts[] = $dialect->quoteIdentifier((string) $col) . ' = ?';
            $bindings[] = $val;
        }
        $sql = 'UPDATE ' . $dialect->quoteIdentifier($table) . ' SET ' . implode(', ', $setParts);
        [$whereSql, $whereBindings] = self::compileWhere($params['where'] ?? [], $dialect);

        if ($whereSql !== '') {
            $sql .= ' WHERE ' . $whereSql;
            $bindings = array_merge($bindings, $whereBindings);
        }

        return [$sql, $bindings];
    }

    /**
     * @param array<string, mixed> $params
     *
     * @return array{0:string,1:array<int, mixed>}
     */
    private static function compileDelete(array $params, SqlDialectInterface $dialect): array
    {
        $table = (string) ($params['table'] ?? '');

        if ($table === '') {
            throw new VersaORMException('Invalid DELETE parameters');
        }
        $sql = 'DELETE FROM ' . $dialect->quoteIdentifier($table);
        [$whereSql, $whereBindings] = self::compileWhere($params['where'] ?? [], $dialect);
        $bindings = [];

        if ($whereSql !== '') {
            $sql .= ' WHERE ' . $whereSql;
            $bindings = array_merge($bindings, $whereBindings);
        }

        return [$sql, $bindings];
    }

    /**
     * Compila cláusulas WHERE.
     *
     * @param list<array{type?:string,operator?:string,column?:string,value:mixed}> $wheres
     *
     * @return array{0:string,1:array<int, mixed>}
     */
    private static function compileWhere(array $wheres, SqlDialectInterface $dialect): array
    {
        /** @var list<array{0:string,1:string}> $parts */
        $parts = [];
        /** @var array<int,mixed> $bindings */
        $bindings = [];

        foreach ($wheres as $w) {
            /** @var array{type?:string,operator?:string,column?:string,value?:mixed} $w */
            $type = strtolower((string) ($w['type'] ?? 'and'));
            $operator = strtoupper((string) ($w['operator'] ?? '='));

            if ($operator === 'RAW' && isset($w['value']) && is_array($w['value']) && isset($w['value']['sql'])) {
                $clause = '(' . $w['value']['sql'] . ')';
                $clauseBindings = [];

                if (isset($w['value']['bindings']) && is_array($w['value']['bindings'])) {
                    /** @var array<int,mixed> $tmp */
                    $tmp = array_values($w['value']['bindings']);
                    $clauseBindings = $tmp;
                }
                $parts[] = [$type, $clause];

                foreach ($clauseBindings as $cb) {
                    $bindings[] = $cb;
                }
                continue;
            }

            $column = (string) ($w['column'] ?? '');
            $value = $w['value'] ?? null;

            match ($operator) {
                'IN', 'NOT IN' => (static function () use ($operator, $value, $type, $column, $dialect, &$parts, &$bindings): void {
                    $vals = is_array($value) ? array_values($value) : [];

                    if ($vals === []) {
                        $parts[] = [$type, $operator === 'IN' ? '1=0' : '1=1'];

                        return;
                    }
                    $ph = implode(', ', array_fill(0, count($vals), '?'));
                    $parts[] = [$type, self::compileSelectPart($column, $dialect) . ' ' . $operator . ' (' . $ph . ')'];

                    foreach ($vals as $v) {
                        $bindings[] = $v;
                    }
                })(),
                'IS NULL', 'IS NOT NULL' => (static function () use ($operator, $type, $column, $dialect, &$parts): void {
                    $parts[] = [$type, self::compileSelectPart($column, $dialect) . ' ' . $operator];
                })(),
                'BETWEEN' => (static function () use ($value, $type, $column, $dialect, &$parts, &$bindings): void {
                    if (is_array($value) && count($value) === 2) {
                        $parts[] = [$type, self::compileSelectPart($column, $dialect) . ' BETWEEN ? AND ?'];
                        $bindings[] = $value[0];
                        $bindings[] = $value[1];
                    }
                })(),
                'EXISTS', 'NOT EXISTS' => throw new VersaORMException('EXISTS subqueries not supported yet in PDO engine'),
                default => (static function () use ($w, $type, $column, $dialect, $value, &$parts, &$bindings): void {
                    $op = $w['operator'] ?? '=';
                    $parts[] = [$type, self::compileSelectPart($column, $dialect) . ' ' . $op . ' ?'];
                    $bindings[] = $value;
                })(),
            };
        }

        if (empty($parts)) {
            return ['', []];
        }

        $sql = '';

        foreach ($parts as $i => $p) {
            [$conj, $clause] = $p; // $p es array{0:string,1:string}
            $sql .= $i === 0 ? $clause : ' ' . strtoupper($conj) . ' ' . $clause;
        }

        return [$sql, $bindings];
    }

    private static function compileSelectPart(string $expr, SqlDialectInterface $dialect): string
    {
        // manejar "table.column as alias" o funciones simples ya validadas en capa superior
        if (stripos($expr, ' as ') !== false) {
            $parts = preg_split('/\s+as\s+/i', $expr);
            $left = $parts[0] ?? '';
            $alias = $parts[1] ?? '';

            return self::compileSelectPart($left, $dialect) . ' AS ' . $dialect->quoteIdentifier($alias);
        }

        // funciones: si parece FUNC(...), no entrecomillar (debe evaluarse antes que table.column)
        if (preg_match('/^[A-Za-z_]+\s*\(.*\)$/', $expr) === 1) {
            return $expr;
        }

        if (str_contains($expr, '.')) {
            [$t, $c] = explode('.', $expr, 2);

            if ($c === '*') {
                return $dialect->quoteIdentifier($t) . '.*';
            }

            return $dialect->quoteIdentifier($t) . '.' . $dialect->quoteIdentifier($c);
        }

        if ($expr === '*') {
            return '*';
        }

        return $dialect->quoteIdentifier($expr);
    }

    private static function compileJoinColumn(string $expr, SqlDialectInterface $dialect): string
    {
        return self::compileSelectPart($expr, $dialect);
    }

    private static function compileTableReference(string $table, SqlDialectInterface $dialect): string
    {
        $table = trim($table);

        // Handle "table as alias" or "table alias"
        if (preg_match('/^([A-Za-z_][A-Za-z0-9_\.]*)(?:\s+as\s+|\s+)([A-Za-z_][A-Za-z0-9_]*)$/i', $table, $m) === 1) {
            $t = $m[1];
            $a = $m[2];

            return $dialect->quoteIdentifier($t) . ' AS ' . $dialect->quoteIdentifier($a);
        }

        return $dialect->quoteIdentifier($table);
    }

    /**
     * @param array<string, mixed> $params
     *
     * @return array{0:string,1:array<int, mixed>}
     */
    private static function compileBatch(string $method, array $params, SqlDialectInterface $dialect): array
    {
        $table = (string) ($params['table'] ?? '');

        if ($table === '') {
            throw new VersaORMException('Missing table for batch operation');
        }

        return match ($method) {
            'insertMany' => (static function () use ($params, $dialect, $table): array {
                /** @var list<array<string,mixed>> $records */
                $records = is_array($params['records'] ?? null) ? $params['records'] : [];

                if (!is_array($records) || $records === []) {
                    throw new VersaORMException('insertMany requires records');
                }
                $columns = array_keys($records[0]);
                $rowPh = '(' . implode(', ', array_fill(0, count($columns), '?')) . ')';
                $sql = 'INSERT INTO ' . self::compileTableReference($table, $dialect)
                    . ' (' . implode(', ', array_map(static fn ($name): string => $dialect->quoteIdentifier($name), $columns)) . ') VALUES ';
                /** @var list<mixed> $bindings */
                $bindings = [];
                $valuesSql = [];

                foreach ($records as $rec) {
                    $valuesSql[] = $rowPh;

                    // Evitar array_merge repetitivo (más GC); push secuencial
                    foreach ($rec as $v) {
                        $bindings[] = $v;
                    }
                }
                $sql .= implode(', ', $valuesSql);

                return [$sql, $bindings];
            })(),
            'updateMany' => self::compileUpdate([
                'table' => $table,
                'data' => $params['data'] ?? [],
                'where' => $params['where'] ?? [],
            ], $dialect),
            'deleteMany' => self::compileDelete([
                'table' => $table,
                'where' => $params['where'] ?? [],
            ], $dialect),
            'upsertMany' => (static function () use ($params, $dialect, $table): array {
                /** @var list<array<string,mixed>> $records */
                $records = is_array($params['records'] ?? null) ? $params['records'] : [];
                /** @var list<string> $unique */
                $unique = is_array($params['unique_keys'] ?? null) ? $params['unique_keys'] : [];
                /** @var list<string> $updateColumns */
                $updateColumns = is_array($params['update_columns'] ?? null) ? $params['update_columns'] : [];

                if (!is_array($records) || $records === []) {
                    throw new VersaORMException('upsertMany requires records');
                }
                $columns = array_keys($records[0]);
                /** @var list<string> $setCols */
                $setCols = empty($updateColumns) ? array_values(array_diff($columns, $unique)) : $updateColumns;
                $rowPh = '(' . implode(', ', array_fill(0, count($columns), '?')) . ')';
                $sql = 'INSERT INTO ' . self::compileTableReference($table, $dialect)
                    . ' (' . implode(', ', array_map(static fn ($name): string => $dialect->quoteIdentifier($name), $columns)) . ') VALUES ';
                /** @var list<mixed> $bindings */
                $bindings = [];
                $valuesSql = [];

                foreach ($records as $rec) {
                    $valuesSql[] = $rowPh;

                    foreach ($rec as $v) {
                        $bindings[] = $v;
                    }
                }
                $sql .= implode(', ', $valuesSql);
                $driverHint = method_exists($dialect, 'getName') ? $dialect->getName() : '';

                if (stripos($driverHint, 'postgres') !== false) {
                    if (empty($unique)) {
                        throw new VersaORMException('PostgreSQL upsert requires unique_keys');
                    }
                    $conflict = '(' . implode(', ', array_map(static fn ($name): string => $dialect->quoteIdentifier($name), $unique)) . ')';
                    $sets = [];

                    foreach ($setCols as $c) {
                        $sets[] = $dialect->quoteIdentifier($c) . ' = EXCLUDED.' . $dialect->quoteIdentifier($c);
                    }
                    $sql .= ' ON CONFLICT ' . $conflict . ' DO UPDATE SET ' . implode(', ', $sets);
                } else {
                    $sets = [];

                    foreach ($setCols as $c) {
                        $qi = $dialect->quoteIdentifier($c);
                        $sets[] = $qi . ' = VALUES(' . $qi . ')';
                    }

                    if ($sets !== []) {
                        $sql .= ' ON DUPLICATE KEY UPDATE ' . implode(', ', $sets);
                    }
                }

                return [$sql, $bindings];
            })(),
            default => throw new VersaORMException('Unknown batch method: ' . $method),
        };
    }
}
