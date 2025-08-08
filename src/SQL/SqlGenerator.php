<?php

declare(strict_types=1);

namespace VersaORM\SQL;

use VersaORM\VersaORMException;

class SqlGenerator
{
    /**
     * Generate SQL and bindings based on action + params from QueryBuilder payload.
     * Returns array [sql, bindings]
     */
    public static function generate(string $action, array $params, SqlDialectInterface $dialect): array
    {
        if ($action === 'raw') {
            $sql = (string)($params['query'] ?? '');
            $bindings = is_array($params['bindings'] ?? null) ? $params['bindings'] : [];
            return [$sql, $bindings];
        }

        if ($action === 'query') {
            $method = (string)($params['method'] ?? 'get');
            // Batch/write methods mapped into query by QueryBuilder
            if (in_array($method, ['insertMany','updateMany','deleteMany','upsertMany'], true)) {
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

    private static function compileSelect(string $method, array $params, SqlDialectInterface $dialect): array
    {
        $table = (string)($params['table'] ?? '');
        if ($table === '') {
            throw new VersaORMException('Missing table for SELECT');
        }

        $select = $params['select'] ?? ['*'];
        $selectSqlParts = [];
        foreach ($select as $sel) {
            if (is_string($sel)) {
                $selectSqlParts[] = self::compileSelectPart($sel, $dialect);
            } elseif (is_array($sel) && isset($sel['type'])) {
                if (($sel['type'] ?? '') === 'raw' && isset($sel['expression'])) {
                    $selectSqlParts[] = (string)$sel['expression'];
                } elseif (($sel['type'] ?? '') === 'subquery') {
                    throw new VersaORMException('Subquery SELECT not supported yet in PDO engine');
                }
            }
        }
        if (empty($selectSqlParts)) {
            $selectSqlParts[] = '*';
        }

        $sql = 'SELECT ' . implode(', ', $selectSqlParts) . ' FROM ' . self::compileTableReference($table, $dialect);
        $bindings = [];

        // JOINS (inner, left, right)
        $joins = $params['joins'] ?? [];
        foreach ($joins as $join) {
            $type = strtolower((string)($join['type'] ?? 'inner'));
            if (!in_array($type, ['inner', 'left', 'right'], true)) {
                throw new VersaORMException('Join type not supported in PDO engine: ' . $type);
            }
            $jt = strtoupper($type) . ' JOIN ' . self::compileTableReference((string)$join['table'], $dialect);
            $first = (string)($join['first_col'] ?? '');
            $op = (string)($join['operator'] ?? '=');
            $second = (string)($join['second_col'] ?? '');
            if ($first === '' || $second === '') {
                throw new VersaORMException('Invalid JOIN columns');
            }
            $sql .= ' ' . $jt . ' ON ' . self::compileJoinColumn($first, $dialect) . ' ' . $op . ' ' . self::compileJoinColumn($second, $dialect);
        }

        // WHERE
        [$whereSql, $whereBindings] = self::compileWhere($params['where'] ?? [], $dialect);
        if ($whereSql !== '') {
            $sql .= ' WHERE ' . $whereSql;
            $bindings = array_merge($bindings, $whereBindings);
        }

        // GROUP BY
        $groupBy = $params['groupBy'] ?? [];
        if (!empty($groupBy)) {
            if (is_array($groupBy) && isset($groupBy['type']) && $groupBy['type'] === 'raw') {
                $sql .= ' GROUP BY ' . (string)($groupBy['expression'] ?? '');
                $bindings = array_merge($bindings, is_array($groupBy['bindings'] ?? null) ? $groupBy['bindings'] : []);
            } else {
                $gb = [];
                foreach ((array)$groupBy as $col) {
                    $gb[] = self::compileSelectPart((string)$col, $dialect);
                }
                if (!empty($gb)) {
                    $sql .= ' GROUP BY ' . implode(', ', $gb);
                }
            }
        }

        // HAVING (simple col op ? )
        $having = $params['having'] ?? [];
        if (!empty($having)) {
            $parts = [];
            foreach ($having as $h) {
                $col = (string)($h['column'] ?? '');
                $op = (string)($h['operator'] ?? '=');
                $parts[] = self::compileSelectPart($col, $dialect) . ' ' . $op . ' ?';
                $bindings[] = $h['value'] ?? null;
            }
            $sql .= ' HAVING ' . implode(' AND ', $parts);
        }

        // ORDER BY (single or raw)
        $orderBy = $params['orderBy'] ?? [];
        if (!empty($orderBy)) {
            $ob = $orderBy[0] ?? [];
            if (isset($ob['type']) && $ob['type'] === 'raw') {
                $sql .= ' ORDER BY ' . (string)($ob['expression'] ?? '');
            } elseif (isset($ob['column'])) {
                $dir = strtoupper((string)($ob['direction'] ?? 'ASC'));
                if (!in_array($dir, ['ASC', 'DESC'], true)) {
                    $dir = 'ASC';
                }
                $sql .= ' ORDER BY ' . self::compileSelectPart((string)$ob['column'], $dialect) . ' ' . $dir;
            }
        }

        // LIMIT/OFFSET
        $sql .= $dialect->compileLimitOffset(
            isset($params['limit']) ? (int)$params['limit'] : null,
            isset($params['offset']) ? (int)$params['offset'] : null
        );

        if ($method === 'count') {
            // Wrap as COUNT(*) OVER subquery
            $countSql = 'SELECT COUNT(*) as count FROM (' . $sql . ') as subq';
            return [$countSql, $bindings];
        }
        if ($method === 'exists') {
            $existsSql = 'SELECT EXISTS(' . $sql . ') as exists_flag';
            return [$existsSql, $bindings];
        }
        if ($method === 'first') {
            // force single row
            $sqlFirst = $sql . ' ' . $dialect->compileLimitOffset(1, null);
            return [$sqlFirst, $bindings];
        }
        // default get
        return [$sql, $bindings];
    }

    private static function compileInsert(array $params, SqlDialectInterface $dialect): array
    {
        $table = (string)($params['table'] ?? '');
        $data = $params['data'] ?? [];
        if ($table === '' || !is_array($data) || empty($data)) {
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

    private static function compileUpdate(array $params, SqlDialectInterface $dialect): array
    {
        $table = (string)($params['table'] ?? '');
        $data = $params['data'] ?? [];
        if ($table === '' || !is_array($data) || empty($data)) {
            throw new VersaORMException('Invalid UPDATE parameters');
        }
        $setParts = [];
        $bindings = [];
        foreach ($data as $col => $val) {
            $setParts[] = $dialect->quoteIdentifier((string)$col) . ' = ?';
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

    private static function compileDelete(array $params, SqlDialectInterface $dialect): array
    {
        $table = (string)($params['table'] ?? '');
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

    private static function compileWhere(array $wheres, SqlDialectInterface $dialect): array
    {
        $parts = [];
        $bindings = [];
        foreach ($wheres as $w) {
            $type = strtolower((string)($w['type'] ?? 'and'));
            $operator = strtoupper((string)($w['operator'] ?? '='));
            if ($operator === 'RAW' && isset($w['value']['sql'])) {
                $clause = '(' . (string)$w['value']['sql'] . ')';
                $clauseBindings = is_array($w['value']['bindings'] ?? null) ? $w['value']['bindings'] : [];
                $parts[] = [$type, $clause];
                $bindings = array_merge($bindings, $clauseBindings);
                continue;
            }

            $column = (string)($w['column'] ?? '');
            $value = $w['value'] ?? null;

            switch ($operator) {
                case 'IN':
                case 'NOT IN':
                    $vals = is_array($value) ? $value : [];
                    if (empty($vals)) {
                        // IN () vacío es inválido; forzar falso/verdadero según NOT IN
                        $parts[] = [$type, $operator === 'IN' ? '1=0' : '1=1'];
                        break;
                    }
                    $ph = implode(', ', array_fill(0, count($vals), '?'));
                    $parts[] = [$type, self::compileSelectPart($column, $dialect) . ' ' . $operator . ' (' . $ph . ')'];
                    $bindings = array_merge($bindings, array_values($vals));
                    break;
                case 'IS NULL':
                case 'IS NOT NULL':
                    $parts[] = [$type, self::compileSelectPart($column, $dialect) . ' ' . $operator];
                    break;
                case 'BETWEEN':
                    if (is_array($value) && count($value) === 2) {
                        $parts[] = [$type, self::compileSelectPart($column, $dialect) . ' BETWEEN ? AND ?'];
                        $bindings[] = $value[0];
                        $bindings[] = $value[1];
                    }
                    break;
                case 'EXISTS':
                case 'NOT EXISTS':
                    throw new VersaORMException('EXISTS subqueries not supported yet in PDO engine');
                default:
                    $parts[] = [$type, self::compileSelectPart($column, $dialect) . ' ' . ($w['operator'] ?? '=') . ' ?'];
                    $bindings[] = $value;
                    break;
            }
        }

        if (empty($parts)) {
            return ['', []];
        }

        $sql = '';
        foreach ($parts as $i => $p) {
            [$conj, $clause] = $p;
            if ($i === 0) {
                $sql .= $clause;
            } else {
                $sql .= ' ' . strtoupper($conj) . ' ' . $clause;
            }
        }
        return [$sql, $bindings];
    }

    private static function compileSelectPart(string $expr, SqlDialectInterface $dialect): string
    {
        // manejar "table.column as alias" o funciones simples ya validadas en capa superior
        if (stripos($expr, ' as ') !== false) {
            [$left, $alias] = preg_split('/\s+as\s+/i', $expr);
            return self::compileSelectPart((string)$left, $dialect) . ' AS ' . $dialect->quoteIdentifier((string)$alias);
        }
        if (str_contains($expr, '.')) {
            [$t, $c] = explode('.', $expr, 2);
            if ($c === '*') {
                return $dialect->quoteIdentifier($t) . '.*';
            }
            return $dialect->quoteIdentifier($t) . '.' . $dialect->quoteIdentifier($c);
        }
        // funciones: si parece FUNC(...), no entrecomillar
        if (preg_match('/^[A-Za-z_]+\s*\(.*\)$/', $expr) === 1) {
            return $expr;
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

    private static function compileBatch(string $method, array $params, SqlDialectInterface $dialect): array
    {
        $table = (string)($params['table'] ?? '');
        if ($table === '') {
            throw new VersaORMException('Missing table for batch operation');
        }
        switch ($method) {
            case 'insertMany':
                $records = $params['records'] ?? [];
                if (!is_array($records) || empty($records)) {
                    throw new VersaORMException('insertMany requires records');
                }
                $columns = array_keys($records[0]);
                $rowPh = '(' . implode(', ', array_fill(0, count($columns), '?')) . ')';
                $sql = 'INSERT INTO ' . self::compileTableReference($table, $dialect)
                    . ' (' . implode(', ', array_map([$dialect, 'quoteIdentifier'], $columns)) . ') VALUES ';
                $bindings = [];
                $valuesSql = [];
                foreach ($records as $rec) {
                    $valuesSql[] = $rowPh;
                    $bindings = array_merge($bindings, array_values($rec));
                }
                $sql .= implode(', ', $valuesSql);
                return [$sql, $bindings];

            case 'updateMany':
                // Reuse compileUpdate
                return self::compileUpdate([
                    'table' => $table,
                    'data' => $params['data'] ?? [],
                    'where' => $params['where'] ?? [],
                ], $dialect);

            case 'deleteMany':
                // Reuse compileDelete (LIMIT could be handled by dialect outside if desired)
                return self::compileDelete([
                    'table' => $table,
                    'where' => $params['where'] ?? [],
                ], $dialect);

            case 'upsertMany':
                // Generate a MySQL style upsert by default; other dialects can be handled by engine level if needed
                $records = $params['records'] ?? [];
                $unique = $params['unique_keys'] ?? [];
                $updateColumns = $params['update_columns'] ?? [];
                if (!is_array($records) || empty($records)) {
                    throw new VersaORMException('upsertMany requires records');
                }
                $columns = array_keys($records[0]);
                // Determine update set columns
                $setCols = !empty($updateColumns) ? $updateColumns : array_values(array_diff($columns, $unique));
                $rowPh = '(' . implode(', ', array_fill(0, count($columns), '?')) . ')';
                $sql = 'INSERT INTO ' . self::compileTableReference($table, $dialect)
                    . ' (' . implode(', ', array_map([$dialect, 'quoteIdentifier'], $columns)) . ') VALUES ';
                $bindings = [];
                $valuesSql = [];
                foreach ($records as $rec) {
                    $valuesSql[] = $rowPh;
                    $bindings = array_merge($bindings, array_values($rec));
                }
                $sql .= implode(', ', $valuesSql);
                // Build ON DUPLICATE KEY UPDATE for MySQL, or ON CONFLICT for PostgreSQL
                $driverHint = method_exists($dialect, 'getName') ? $dialect->getName() : '';
                if (stripos($driverHint, 'postgres') !== false) {
                    // Postgres: need conflict target
                    if (empty($unique)) {
                        throw new VersaORMException('PostgreSQL upsert requires unique_keys');
                    }
                    $conflict = '(' . implode(', ', array_map([$dialect, 'quoteIdentifier'], $unique)) . ')';
                    $sets = [];
                    foreach ($setCols as $c) {
                        $sets[] = $dialect->quoteIdentifier($c) . ' = EXCLUDED.' . $dialect->quoteIdentifier($c);
                    }
                    $sql .= ' ON CONFLICT ' . $conflict . ' DO UPDATE SET ' . implode(', ', $sets);
                } else {
                    // Default to MySQL style
                    $sets = [];
                    foreach ($setCols as $c) {
                        $qi = $dialect->quoteIdentifier($c);
                        $sets[] = $qi . ' = VALUES(' . $qi . ')';
                    }
                    if (!empty($sets)) {
                        $sql .= ' ON DUPLICATE KEY UPDATE ' . implode(', ', $sets);
                    }
                }
                return [$sql, $bindings];
        }
        throw new VersaORMException('Unknown batch method: ' . $method);
    }
}
