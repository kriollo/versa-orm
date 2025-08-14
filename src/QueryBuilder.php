<?php

declare(strict_types=1);

namespace VersaORM;

use Closure;
use Exception;
use ReflectionClass;
use Throwable;
use VersaORM\Relations\Relation;
use VersaORM\SQL\PdoEngine;

use function array_key_exists;
use function assert;
use function count;
use function in_array;
use function is_array;
use function is_callable;
use function is_int;
use function is_string;
use function sprintf;
use function strlen;

/**
 * QueryBuilder - Constructor de consultas para VersaORM.
 *
 * PROPÓSITO: Construir consultas SQL de forma fluida
 * ARQUITECTURA CLARA:
 *
 * MÉTODOS QUE DEVUELVEN ARRAYS (datos exportables para JSON/API):
 * - get() - Array de arrays con datos
 * - getAll() - Alias de get()
 * - first() - Array con primer registro o null
 * - count() - Entero
 * - exists() - Boolean
 *
 * MÉTODOS QUE DEVUELVEN OBJETOS MANIPULABLES (VersaModel):
 * - findAll() - Array de objetos VersaModel
 * - findOne() - Objeto VersaModel o null
 * - find(id) - Objeto VersaModel o null
 * - dispense() - Nuevo objeto VersaModel vacío
 *
 * @version 1.0.0
 *
 * @author  VersaORM Team
 * @license MIT
 */
class QueryBuilder
{
    // Puede ser array (config) o instancia de VersaORM

    private string $table;

    /** @var list<SelectRaw|SelectSub|string> */
    private array $selects = [];

    /** @var list<WhereEntry> */
    private array $wheres = [];

    /**
     * Lista de JOINs.
     * Admite joins simples y subqueries con alias y bindings.
     *
     * @var list<array{
     *   type:string,
     *   table:string,
     *   first?:string,
     *   first_col?:string,
     *   operator:string,
     *   second?:string,
     *   second_col?:string,
     *   alias?:string,
     *   subquery?:string,
     *   subquery_bindings?:array<int,mixed>
     * }>
     */
    private array $joins = [];

    /**
     * @var array<string, array<mixed|string>|string>|null
     */
    private ?array $orderBy = null;

    private ?int $limit = null;

    private ?int $offset = null;

    /**
     * @var array<int, string>|array<string, mixed>
     */
    private array $groupBy = [];

    /**
     * Lista de condiciones HAVING.
     * Shape: {column, operator, value, connector}
     * Se admite lista vacía o no vacía.
     *
     * /** @var list<HavingEntry> */
    private array $having = [];

    /**
     * Relaciones eager a cargar.
     * Campos opcionales según tipo de relación.
     *
     * @var list<array{
     *   name:string,
     *   type?:string,
     *   related_table?:string,
     *   foreign_key?:mixed,
     *   local_key?:mixed,
     *   owner_key?:mixed,
     *   pivot_table?:mixed,
     *   foreign_pivot_key?:mixed,
     *   related_pivot_key?:mixed,
     *   parent_key?:mixed,
     *   related_key?:mixed
     * }>
     */
    private array $with = [];

    /**
     * Clase de modelo asociada (FQCN) o null.
     *
     * @var class-string<VersaModel>|null
     */
    private ?string $modelClass = null;

    /** @var list<array<string,mixed>> */
    private array $lazyOperations = [];

    private bool $isLazy = false;

    /**
     * @param array<string,mixed>|VersaORM|null $orm
     */
    public function __construct(private $orm, string $table, ?string $modelClass = null)
    {
        // Validar identificador/alias de tabla inmediatamente para prevenir casos maliciosos
        if (!$this->isSafeIdentifier($table)) {
            throw new VersaORMException(sprintf('Invalid or malicious table name detected (error): %s', $table));
        }
        $this->table = $table;

        if (is_string($modelClass) && $modelClass !== '' && class_exists($modelClass) && is_a($modelClass, VersaModel::class, true)) {
            // @var class-string<VersaModel> $modelClass
            $this->modelClass = $modelClass;
        } else {
            $this->modelClass = null;
        }
    }

    /**
     * Especifica la tabla de origen para la consulta.
     */
    public function from(string $table): self
    {
        if (!$this->isSafeIdentifier($table)) {
            throw new VersaORMException(sprintf('Invalid or malicious table name detected: %s', $table));
        }
        $this->table = $table;

        return $this;
    }

    /**
     * Especifica las columnas a seleccionar.
     *
     * @param array<int, string> $columns
     */
    public function select(array $columns = ['*']): self
    {
        if ($columns === []) {
            $columns = ['*'];
        }

        foreach ($columns as $column) {
            if (!$this->isSafeIdentifier($column)) {
                throw new VersaORMException(sprintf('Invalid or malicious column name detected: %s', $column));
            }
        }
        $this->selects = $columns;

        return $this;
    }

    /**
     * Especifica una expresión SQL raw para el SELECT.
     * ADVERTENCIA: Use con precaución para evitar inyección SQL.
     *
     * @param array<int, mixed> $bindings
     */
    public function selectRaw(string $expression, array $bindings = []): self
    {
        if (in_array(trim($expression), ['', '0'], true)) {
            throw new VersaORMException('selectRaw expression cannot be empty');
        }

        // Validación básica de seguridad
        if (!$this->isSafeRawExpression($expression)) {
            throw new VersaORMException('Potentially unsafe SQL expression detected in selectRaw');
        }

        $this->selects[] = [
            'type' => 'raw',
            'expression' => $expression,
            'bindings' => $bindings,
        ];

        return $this;
    }

    /**
     * Añade una subconsulta al SELECT con alias.
     *
     * @param Closure|QueryBuilder $callback
     */
    public function selectSubQuery($callback, string $alias): self
    {
        if (!$this->isSafeIdentifier($alias)) {
            throw new VersaORMException(sprintf('Invalid alias name in selectSubQuery: %s', $alias));
        }

        $subQuery = $this->buildSubQuery($callback);

        $this->selects[] = [
            'type' => 'subquery',
            'subquery' => $subQuery,
            'alias' => $alias,
        ];

        return $this;
    }

    /**
     * Añade una cláusula WHERE.
     */
    public function where(string $column, string $operator, mixed $value): self
    {
        $this->addWhereEntry($column, $operator, $value, 'and');

        return $this;
    }

    /**
     * Añade una cláusula OR WHERE.
     */
    public function orWhere(string $column, string $operator, mixed $value): self
    {
        $this->addWhereEntry($column, $operator, $value, 'or');

        return $this;
    }

    /**
     * Añade una cláusula WHERE IN.
     *
     * @param array<int, mixed> $values
     */
    public function whereIn(string $column, array $values): self
    {
        $this->addWhereEntry($column, 'IN', $values, 'and');

        return $this;
    }

    /**
     * Añade una cláusula WHERE NOT IN.
     *
     * @param array<int, mixed> $values
     */
    public function whereNotIn(string $column, array $values): self
    {
        $this->addWhereEntry($column, 'NOT IN', $values, 'and');

        return $this;
    }

    /**
     * Añade una cláusula WHERE IS NULL.
     */
    public function whereNull(string $column): self
    {
        $this->addWhereEntry($column, 'IS NULL', null, 'and');

        return $this;
    }

    /**
     * Añade una cláusula WHERE IS NOT NULL.
     */
    public function whereNotNull(string $column): self
    {
        $this->addWhereEntry($column, 'IS NOT NULL', null, 'and');

        return $this;
    }

    /**
     * Añade una cláusula WHERE BETWEEN.
     */
    public function whereBetween(string $column, mixed $min, mixed $max): self
    {
        $this->addWhereEntry($column, 'BETWEEN', [$min, $max], 'and');

        return $this;
    }

    /**
     * Añade una cláusula WHERE con SQL raw.
     *
     * @param array<int, mixed> $bindings
     */
    public function whereRaw(string $sql, array $bindings = []): self
    {
        if (!$this->isSafeRawExpression($sql)) {
            throw new VersaORMException('Potentially unsafe SQL expression detected in whereRaw');
        }
        $this->addWhereEntry('', 'RAW', ['sql' => $sql, 'bindings' => $bindings], 'and');

        return $this;
    }

    /**
     * Añade una subconsulta en WHERE.
     *
     * @param Closure|QueryBuilder $callback
     */
    public function whereSubQuery(string $column, string $operator, $callback): self
    {
        if (!$this->isSafeIdentifier($column)) {
            throw new VersaORMException(sprintf('Invalid column name in whereSubQuery: %s', $column));
        }

        $validOperators = ['=', '!=', '<>', '>', '<', '>=', '<=', 'IN', 'NOT IN', 'EXISTS', 'NOT EXISTS'];

        if (!in_array(strtoupper($operator), $validOperators, true)) {
            throw new VersaORMException(sprintf('Invalid operator in whereSubQuery: %s', $operator));
        }

        $subQuery = $this->buildSubQuery($callback);

        $this->wheres[] = [
            'column' => $column,
            'operator' => strtoupper($operator),
            'value' => $subQuery,
            'type' => 'and',
            'subquery' => true,
        ];

        return $this;
    }

    /**
     * Añade una subconsulta EXISTS en WHERE.
     *
     * @param Closure|QueryBuilder $callback
     */
    public function whereExists($callback): self
    {
        $subQuery = $this->buildSubQuery($callback);

        $this->wheres[] = [
            'column' => '',
            'operator' => 'EXISTS',
            'value' => $subQuery,
            'type' => 'and',
            'subquery' => true,
        ];

        return $this;
    }

    /**
     * Añade una subconsulta NOT EXISTS en WHERE.
     *
     * @param Closure|QueryBuilder $callback
     */
    public function whereNotExists($callback): self
    {
        $subQuery = $this->buildSubQuery($callback);

        $this->wheres[] = [
            'column' => '',
            'operator' => 'NOT EXISTS',
            'value' => $subQuery,
            'type' => 'and',
            'subquery' => true,
        ];

        return $this;
    }

    /**
     * Añade una cláusula HAVING.
     */
    public function having(string $column, string $operator, mixed $value): self
    {
        $this->having[] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value,
            'connector' => 'AND',
        ];

        return $this;
    }

    /**
     * Añade un INNER JOIN.
     */
    public function join(string $table, string $firstCol = '', string $operator = '=', string $secondCol = ''): self
    {
        $entry = [
            'type' => 'inner',
            'table' => $table,
            'first_col' => '',
            'operator' => '=',
            'second_col' => '',
            'conditions' => [],
        ];

        if ($firstCol !== '' && $secondCol !== '') {
            $entry['first_col'] = $firstCol;
            $entry['operator'] = $operator;
            $entry['second_col'] = $secondCol;
            $entry['conditions'][] = [
                'local' => $firstCol,
                'operator' => $operator,
                'foreign' => $secondCol,
                'boolean' => 'AND',
            ];
        }
        $this->joins[] = $entry;

        return $this;
    }

    /**
     * Añade un LEFT JOIN.
     */
    public function leftJoin(string $table, string $firstCol = '', string $operator = '=', string $secondCol = ''): self
    {
        $entry = [
            'type' => 'left',
            'table' => $table,
            'first_col' => '',
            'operator' => '=',
            'second_col' => '',
            'conditions' => [],
        ];

        if ($firstCol !== '' && $secondCol !== '') {
            $entry['first_col'] = $firstCol;
            $entry['operator'] = $operator;
            $entry['second_col'] = $secondCol;
            $entry['conditions'][] = [
                'local' => $firstCol,
                'operator' => $operator,
                'foreign' => $secondCol,
                'boolean' => 'AND',
            ];
        }
        $this->joins[] = $entry;

        return $this;
    }

    /**
     * Añade un RIGHT JOIN.
     */
    public function rightJoin(string $table, string $firstCol = '', string $operator = '=', string $secondCol = ''): self
    {
        $entry = [
            'type' => 'right',
            'table' => $table,
            'first_col' => '',
            'operator' => '=',
            'second_col' => '',
            'conditions' => [],
        ];

        if ($firstCol !== '' && $secondCol !== '') {
            $entry['first_col'] = $firstCol;
            $entry['operator'] = $operator;
            $entry['second_col'] = $secondCol;
            $entry['conditions'][] = [
                'local' => $firstCol,
                'operator' => $operator,
                'foreign' => $secondCol,
                'boolean' => 'AND',
            ];
        }
        $this->joins[] = $entry;

        return $this;
    }

    /**
     * Añade un FULL OUTER JOIN.
     */
    public function fullOuterJoin(string $table, string $firstCol = '', string $operator = '=', string $secondCol = ''): self
    {
        $entry = [
            'type' => 'full_outer',
            'table' => $table,
            'first_col' => '',
            'operator' => '=',
            'second_col' => '',
            'conditions' => [],
        ];

        if ($firstCol !== '' && $secondCol !== '') {
            $entry['first_col'] = $firstCol;
            $entry['operator'] = $operator;
            $entry['second_col'] = $secondCol;
            $entry['conditions'][] = [
                'local' => $firstCol,
                'operator' => $operator,
                'foreign' => $secondCol,
                'boolean' => 'AND',
            ];
        }
        $this->joins[] = $entry;

        return $this;
    }

    /**
     * Añade un CROSS JOIN.
     */
    public function crossJoin(string $table): self
    {
        $this->joins[] = [
            'type' => 'cross',
            'table' => $table,
            'first_col' => '',
            'operator' => '',
            'second_col' => '',
            'conditions' => [],
        ];

        return $this;
    }

    /**
     * Añade un NATURAL JOIN.
     * NATURAL JOIN automáticamente une tablas basado en columnas con el mismo nombre.
     */
    public function naturalJoin(string $table): self
    {
        $this->joins[] = [
            'type' => 'natural',
            'table' => $table,
            'first_col' => '',
            'operator' => '',
            'second_col' => '',
            'conditions' => [],
        ];

        return $this;
    }

    /**
     * Añade un JOIN con una subconsulta.
     *
     * @param Closure|QueryBuilder $subquery
     */
    public function joinSub($subquery, string $alias, string $firstCol, string $operator, string $secondCol): self
    {
        if (!$this->isSafeIdentifier($alias)) {
            throw new VersaORMException(sprintf('Invalid alias name in joinSub: %s', $alias));
        }

        if (!$this->isSafeIdentifier($firstCol) || !$this->isSafeIdentifier($secondCol)) {
            throw new VersaORMException('Invalid column names in joinSub');
        }

        // Convert the subquery to SQL and extract bindings for the Rust engine
        $subqueryData = $this->convertSubqueryToSql($subquery);

        $this->joins[] = [
            'type' => 'inner',
            'table' => $alias,
            'first_col' => $firstCol,
            'operator' => $operator,
            'second_col' => $secondCol,
            'subquery' => $subqueryData['sql'],
            'subquery_bindings' => $subqueryData['bindings'],
            'alias' => $alias,
            'conditions' => [
                [
                    'local' => $firstCol,
                    'operator' => $operator,
                    'foreign' => $secondCol,
                    'boolean' => 'AND',
                ],
            ],
        ];

        return $this;
    }

    /**
     * Añade condición adicional a la última cláusula JOIN (patrón encadenado on()).
     */
    public function on(string $local, string $operator, string $foreign, string $boolean = 'AND'): self
    {
        $count = count($this->joins);

        if ($count === 0) {
            throw new VersaORMException('Cannot add ON condition: no JOIN defined yet.');
        }
        $idx = $count - 1;

        if (!isset($this->joins[$idx]['conditions']) || !is_array($this->joins[$idx]['conditions'])) {
            $this->joins[$idx]['conditions'] = [];
        }
        $this->joins[$idx]['conditions'][] = [
            'local' => $local,
            'operator' => $operator,
            'foreign' => $foreign,
            'boolean' => strtoupper($boolean) === 'OR' ? 'OR' : 'AND',
        ];

        if (empty($this->joins[$idx]['first_col'])) {
            $this->joins[$idx]['first_col'] = $local;
            $this->joins[$idx]['operator'] = $operator;
            $this->joins[$idx]['second_col'] = $foreign;
        }

        return $this;
    }

    /**
     * Agrupa los resultados.
     *
     * @param array<int, string>|string $columns
     */
    public function groupBy(array|string $columns): self
    {
        if (is_string($columns)) {
            $columns = [$columns];
        }

        foreach ($columns as $column) {
            if (!$this->isSafeIdentifier($column)) {
                throw new VersaORMException(sprintf('Invalid or malicious column name in GROUP BY: %s', $column));
            }
        }

        $this->groupBy = $columns;

        return $this;
    }

    /**
     * Especifica una expresión SQL raw para GROUP BY.
     * ADVERTENCIA: Use con precaución para evitar inyección SQL.
     *
     * @param array<int, mixed> $bindings
     */
    public function groupByRaw(string $expression, array $bindings = []): self
    {
        if (in_array(trim($expression), ['', '0'], true)) {
            throw new VersaORMException('groupByRaw expression cannot be empty');
        }

        // Validación básica de seguridad
        if (!$this->isSafeRawExpression($expression)) {
            throw new VersaORMException('Potentially unsafe SQL expression detected in groupByRaw');
        }

        $this->groupBy = [
            'type' => 'raw',
            'expression' => $expression,
            'bindings' => $bindings,
        ];

        return $this;
    }

    /**
     * Ordena los resultados.
     */
    public function orderBy(string $column, string $direction = 'asc'): self
    {
        // Validate column name for security
        if (!$this->isSafeIdentifier($column)) {
            throw new VersaORMException(sprintf('Invalid or malicious column name in ORDER BY: %s', $column));
        }

        // Validate direction to prevent injection
        $direction = strtoupper($direction);

        if (!in_array($direction, ['ASC', 'DESC'], true)) {
            throw new VersaORMException(sprintf('Invalid ORDER BY direction. Only ASC and DESC are allowed: %s', $direction));
        }

        $this->orderBy = ['column' => $column, 'direction' => $direction];

        return $this;
    }

    /**
     * Especifica una expresión SQL raw para ORDER BY.
     * ADVERTENCIA: Use con precaución para evitar inyección SQL.
     *
     * @param array<int, mixed> $bindings
     */
    public function orderByRaw(string $expression, array $bindings = []): self
    {
        if (in_array(trim($expression), ['', '0'], true)) {
            throw new VersaORMException('orderByRaw expression cannot be empty');
        }

        // Validación básica de seguridad
        if (!$this->isSafeRawExpression($expression)) {
            throw new VersaORMException('Potentially unsafe SQL expression detected in orderByRaw');
        }

        $this->orderBy = [
            'type' => 'raw',
            'expression' => $expression,
            'bindings' => $bindings,
        ];

        return $this;
    }

    /**
     * Limita el número de resultados.
     *
     * @param int $count
     */
    public function limit(int|string $count): self
    {
        $this->limit = (int) $count;

        return $this;
    }

    /**
     * Especifica el punto de inicio para la paginación.
     */
    public function offset(int $count): self
    {
        $this->offset = $count;

        return $this;
    }

    /**
     * Especifica las relaciones a cargar.
     *
     * @param array<int, string>|string $relations
     */
    public function with($relations): self
    {
        if (is_string($relations)) {
            $relations = [$relations];
        }

        if ($this->modelClass === null || $this->modelClass === '' || $this->modelClass === '0' || !class_exists($this->modelClass)) {
            throw new Exception('Cannot eager load relations without a valid model class.');
        }

        $resolvedRelations = [];

        foreach ($relations as $relationName) {
            if (!method_exists($this->modelClass, $relationName)) {
                throw new Exception(sprintf("Relation method '%s' not found in model '%s'.", $relationName, $this->modelClass));
            }

            // Crear una instancia temporal del modelo para llamar al método de relación
            // Para evitar problemas con el ORM en la instancia temporal, pasamos null
            $tempModel = new $this->modelClass($this->table, null);

            $relationInstance = $tempModel->{$relationName}();

            if (!$relationInstance instanceof Relation) {
                throw new Exception(sprintf("Method '%s' in model '%s' does not return a valid Relation instance.", $relationName, $this->modelClass));
            }

            $relationType = (new ReflectionClass($relationInstance))->getShortName();
            $relationData = [
                'name' => $relationName,
                'type' => $relationType,
                'related_table' => $relationInstance->query->getTable(),
            ];

            // Extraer claves específicas según el tipo de relación
            switch ($relationType) {
                case 'HasOne':
                case 'HasMany':
                    // @var \VersaORM\Relations\HasOne|\VersaORM\Relations\HasMany $relationInstance
                    $relationData['foreign_key'] = $relationInstance->foreignKey;
                    $relationData['local_key'] = $relationInstance->localKey;
                    break;
                case 'BelongsTo':
                    // @var \VersaORM\Relations\BelongsTo $relationInstance
                    $relationData['foreign_key'] = $relationInstance->foreignKey;
                    $relationData['owner_key'] = $relationInstance->ownerKey; // Usar owner_key para BelongsTo
                    break;
                case 'BelongsToMany':
                    // @var \VersaORM\Relations\BelongsToMany $relationInstance
                    $relationData['pivot_table'] = $relationInstance->pivotTable;
                    $relationData['foreign_pivot_key'] = $relationInstance->foreignPivotKey;
                    $relationData['related_pivot_key'] = $relationInstance->relatedPivotKey;
                    $relationData['parent_key'] = $relationInstance->parentKey;
                    $relationData['related_key'] = $relationInstance->relatedKey;
                    break;
            }
            $resolvedRelations[] = $relationData;
        }

        $this->with = $resolvedRelations;

        return $this;
    }

    // ========== MÉTODOS QUE DEVUELVEN OBJETOS MANIPULABLES ==========

    /**
     * Ejecuta la consulta SELECT y devuelve un array de objetos VersaModel manipulables.
     *
     * @return array<int, VersaModel>
     */
    public function findAll(): array
    {
        $raw = $this->execute('get');
        $models = [];
        $hydrationStart = microtime(true);

        if (!is_array($raw)) {
            return $models;
        }
        $modelClass = (is_string($this->modelClass) && $this->modelClass !== '' && is_a($this->modelClass, VersaModel::class, true))
            ? $this->modelClass
            : VersaModel::class;
        /** @var class-string<VersaModel> $modelClass */

        // FAST-PATH: sin relaciones, modelo base (VersaModel exactamente), sin select personalizado (usa '*'), sin having ni window ni unions.
        $canFastPath = $this->with === []
            && $modelClass === VersaModel::class
            && ($this->selects === [] || (count($this->selects) === 1 && $this->selects[0] === '*'))
            && $this->groupBy === []
            && $this->having === [];

        if ($canFastPath) {
            try {
                $fpStart = microtime(true);

                foreach ($raw as $row) {
                    if (!is_array($row)) {
                        continue;
                    }
                    $m = new VersaModel($this->table, $this->orm);
                    // Asignar atributos directamente (evita separación relaciones/casts costosos); loadInstance hace lógica adicional.
                    // Dado que no hay relaciones en fast-path, podemos setear attributes internamente usando reflexión simple.
                    // Para mantener compatibilidad, reutilizamos loadInstance (micro-optimización posible a futuro si es hotspot).
                    $m->loadInstance($row);
                    // Aplicar casting tipo a nivel de export ahora para asegurar consistencia inmediata
                    $m->export(); // export realiza casting; atributos internos siguen crudos pero acceso externo es consistente
                    $models[] = $m;
                }

                if ($this->orm instanceof VersaORM) {
                    $cfgEngine = strtolower((string) ($this->orm->getConfig()['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

                    if ($cfgEngine === 'pdo' && class_exists(PdoEngine::class)) {
                        $elapsedFp = (microtime(true) - $fpStart) * 1000;
                        PdoEngine::recordHydrationFast(count($models), $elapsedFp);
                    }
                }

                return $models; // Terminar aquí (fast-path completado)
            } catch (Throwable) {
                // fallback silencioso al camino normal
            }
        }

        foreach ($raw as $row) {
            if (!is_array($row)) {
                continue;
            }
            $model = new $modelClass($this->table, $this->orm);
            $model->loadInstance($row);

            foreach ($this->with as $relation) {
                $name = $relation['name'] ?? null;

                if (is_string($name) && $name !== '') {
                    $model->getRelationValue($name);
                }
            }
            $models[] = $model;
        }

        // Registrar métricas de hidratación si el motor PDO está activo
        try {
            if ($this->orm instanceof VersaORM) {
                $cfgEngine = strtolower((string) ($this->orm->getConfig()['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

                if ($cfgEngine === 'pdo' && class_exists(PdoEngine::class)) {
                    $elapsed = (microtime(true) - $hydrationStart) * 1000; // ms
                    PdoEngine::recordHydration(count($models), $elapsed);
                }
            }
        } catch (Throwable) {
            // silencioso: no romper flujo si métricas fallan
        }

        return $models;
    }

    // ========== MÉTODOS QUE DEVUELVEN ARRAYS (para JSON/API) ==========

    /**
     * Ejecuta la consulta SELECT y devuelve array de arrays de datos (para JSON/API).
     *
     * @return array<int, array<string, mixed>>
     */
    public function get(): array
    {
        $raw = $this->execute('get');

        if (!is_array($raw)) {
            return [];
        }
        $rows = array_values(array_filter($raw, 'is_array'));
        // Construir modelo (base o personalizado) para aplicar casting/accessors consistente
        $modelClass = (is_string($this->modelClass) && $this->modelClass !== '' && is_a($this->modelClass, VersaModel::class, true))
            ? $this->modelClass
            : VersaModel::class;
        /** @var class-string<VersaModel> $modelClass */
        $exported = [];

        foreach ($rows as $row) {
            try {
                $m = new $modelClass($this->table, $this->orm);
                $m->loadInstance($row);
                // Export aplica casting; garantizar consistencia
                $exported[] = $m->export();
            } catch (Throwable) {
                // Fallback al row original si algo falla
                $exported[] = $row;
            }
        }

        return $exported;
    }

    /**
     * Alias de get() - devuelve array de arrays de datos.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getAll(): array
    {
        return $this->get();
    }

    /**
     * Obtiene el primer registro como array (para JSON/API).
     *
     * @return array<string, mixed>|null
     */
    public function firstArray(): ?array
    {
        $row = $this->execute('first');

        if (!is_array($row)) {
            return null;
        }
        $modelClass = (is_string($this->modelClass) && $this->modelClass !== '' && is_a($this->modelClass, VersaModel::class, true))
            ? $this->modelClass
            : VersaModel::class;

        try {
            $m = new $modelClass($this->table, $this->orm);
            $m->loadInstance($row);

            return $m->export(); // export con casting
        } catch (Throwable) {
            return $row; // fallback sin casting
        }
    }

    /**
     * Ejecuta la consulta y devuelve el primer objeto resultado como VersaModel, o null.
     */
    public function findOne(): ?VersaModel
    {
        $hydrationStart = microtime(true);
        $row = $this->execute('first');

        if (!is_array($row) || $row === []) {
            return null;
        }
        $modelClass = (is_string($this->modelClass) && $this->modelClass !== '' && is_a($this->modelClass, VersaModel::class, true))
            ? $this->modelClass
            : VersaModel::class;

        /** @var class-string<VersaModel> $modelClass */
        // Fast-path single row para VersaModel base sin relaciones
        if ($this->with === [] && $modelClass === VersaModel::class) {
            try {
                $fpStart = microtime(true);
                $m = new VersaModel($this->table, $this->orm);
                $m->loadInstance($row); // simple; mapping directo interno

                if ($this->orm instanceof VersaORM) {
                    $cfgEngine = strtolower((string) ($this->orm->getConfig()['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

                    if ($cfgEngine === 'pdo' && class_exists(PdoEngine::class)) {
                        $elapsedFp = (microtime(true) - $fpStart) * 1000;
                        PdoEngine::recordHydrationFast(1, $elapsedFp);
                    }
                }

                return $m;
            } catch (Throwable) {
                // fallback normal
            }
        }
        $model = new $modelClass($this->table, $this->orm);
        $model->loadInstance($row);

        foreach ($this->with as $relation) {
            $name = $relation['name'] ?? null;

            if (is_string($name) && $name !== '') {
                $model->getRelationValue($name);
            }
        }

        try {
            if ($this->orm instanceof VersaORM) {
                $cfgEngine = strtolower((string) ($this->orm->getConfig()['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

                if ($cfgEngine === 'pdo' && class_exists(PdoEngine::class)) {
                    $elapsed = (microtime(true) - $hydrationStart) * 1000; // ms
                    PdoEngine::recordHydration(1, $elapsed);
                }
            }
        } catch (Throwable) {
        }

        return $model;
    }

    /**
     * Busca un registro por su clave primaria.
     */
    public function find(mixed $id, string $pk = 'id'): ?VersaModel
    {
        return $this->where($pk, '=', $id)->first();
    }

    /**
     * Retrieves the first result from the executed query and returns it as a VersaModel instance.
     *
     * Executes the query using the 'first' mode, which is expected to return a single result.
     * If a result is found, a new VersaModel instance is created, loaded with the result data, and returned.
     * If no result is found, returns null.
     *
     * @return VersaModel|null the first result as a VersaModel instance, or null if no result is found
     */
    public function first(): ?VersaModel
    {
        $hydrationStart = microtime(true);
        $row = $this->execute('first');

        if (!is_array($row) || $row === []) {
            return null;
        }
        $modelClass = (is_string($this->modelClass) && $this->modelClass !== '' && is_a($this->modelClass, VersaModel::class, true))
            ? $this->modelClass
            : VersaModel::class;

        /** @var class-string<VersaModel> $modelClass */
        if ($this->with === [] && $modelClass === VersaModel::class) {
            try {
                $fpStart = microtime(true);
                $m = new VersaModel($this->table, $this->orm);
                $m->loadInstance($row);

                if ($this->orm instanceof VersaORM) {
                    $cfgEngine = strtolower((string) ($this->orm->getConfig()['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

                    if ($cfgEngine === 'pdo' && class_exists(PdoEngine::class)) {
                        $elapsedFp = (microtime(true) - $fpStart) * 1000;
                        PdoEngine::recordHydrationFast(1, $elapsedFp);
                    }
                }

                return $m;
            } catch (Throwable) {
            }
        }
        $model = new $modelClass($this->table, $this->orm);
        $model->loadInstance($row);

        try {
            if ($this->orm instanceof VersaORM) {
                $cfgEngine = strtolower((string) ($this->orm->getConfig()['engine'] ?? (getenv('VOR_ENGINE') ?: 'pdo')));

                if ($cfgEngine === 'pdo' && class_exists(PdoEngine::class)) {
                    $elapsed = (microtime(true) - $hydrationStart) * 1000; // ms
                    PdoEngine::recordHydration(1, $elapsed);
                }
            }
        } catch (Throwable) {
        }

        return $model;
    }

    /**
     * Ejecuta una consulta de conteo.
     */
    public function count(): int
    {
        $result = $this->execute('count');

        if (is_numeric($result)) {
            return (int) $result;
        }

        return 0;
    }

    /**
     * Verifica si existen registros que coincidan con la consulta.
     */
    public function exists(): bool
    {
        return (bool) $this->execute('exists');
    }

    /**
     * Inserta un nuevo registro.
     *
     * @param array<string, mixed> $data
     */
    public function insert(array $data): bool
    {
        $result = $this->execute('insert', $data);

        return is_int($result) && $result > 0;
    }

    /**
     * Inserta un registro y devuelve su ID autoincremental.
     *
     * @param array<string, mixed> $data
     *
     * @return int|null El ID del registro insertado (como entero), o null si no se pudo obtener el ID
     */
    public function insertGetId(array $data): ?int
    {
        $result = $this->execute('insertGetId', $data);

        if (is_int($result)) {
            return $result;
        }

        if (is_string($result) && $result !== '' && is_numeric($result)) {
            return (int) $result;
        }

        return null;
    }

    /**
     * Actualiza los registros que coincidan con las cláusulas WHERE.
     *
     * @param array<string, mixed> $data
     */
    public function update(array $data): self
    {
        $this->execute('update', $data);

        return $this;
    }

    /**
     * Elimina los registros que coincidan con las cláusulas WHERE.
     */
    public function delete(): ?VersaModel
    {
        $this->execute('delete');

        return null;
    }

    /**
     * Crear un nuevo objeto (dispense).
     */
    public function dispense(): VersaModel
    {
        error_log('[DEBUG] Executing SQL with QueryBuilder');

        return new VersaModel($this->table, $this->orm);
    }

    /**
     * Obtiene el nombre de la tabla asociada a este QueryBuilder.
     */
    public function getTable(): string
    {
        return $this->table;
    }

    /**
     * Obtiene una instancia del modelo asociado a este QueryBuilder.
     */
    public function getModelInstance(): VersaModel
    {
        $modelClass = $this->modelClass !== null && $this->modelClass !== '' && $this->modelClass !== '0' ? $this->modelClass : VersaModel::class;
        /**
         * @var VersaModel $model
         */
        $model = new $modelClass($this->table, $this->orm);
        assert($model instanceof VersaModel);

        return $model;
    }

    // ======================================================================
    // BATCH OPERATIONS (LOTE) - Tarea 2.2
    // ======================================================================

    /**
     * Inserta múltiples registros en una sola operación batch optimizada.
     * Utiliza INSERT INTO table (cols) VALUES (val1), (val2), ... para máximo rendimiento.
     *
     * @param array<int, array<string, mixed>> $records Array de arrays asociativos con los datos a insertar
     * @param int $batchSize Tamaño del lote para operaciones muy grandes (default:
     *                       1000)
     *
     * @throws VersaORMException Si los datos son inválidos o la operación falla
     *
     * @return array<string, mixed> información sobre la operación: total_inserted, batches_processed, etc
     */
    public function insertMany(array $records, int $batchSize = 1000): array
    {
        if ($records === []) {
            throw new VersaORMException('insertMany requires at least one record to insert');
        }

        // Validar que todos los registros tengan la misma estructura
        $firstKeys = array_keys($records[0]);

        foreach ($records as $index => $record) {
            if (!is_array($record) || $record === []) {
                throw new VersaORMException(sprintf('Record at index %d is invalid or empty', $index));
            }

            $currentKeys = array_keys($record);

            if ($currentKeys !== $firstKeys) {
                throw new VersaORMException(
                    sprintf(
                        'Record at index %d has different columns. Expected: [%s], Got: [%s]',
                        $index,
                        implode(', ', $firstKeys),
                        implode(', ', $currentKeys),
                    ),
                );
            }

            // Validar nombres de columnas por seguridad
            foreach ($currentKeys as $column) {
                if (!$this->isSafeIdentifier($column)) {
                    throw new VersaORMException(sprintf('Invalid or malicious column name detected: %s', $column));
                }
            }
        }

        // Validar tamaño de lote
        if ($batchSize <= 0 || $batchSize > 10000) {
            throw new VersaORMException('Batch size must be between 1 and 10000');
        }

        $params = [
            'records' => $records,
            'batch_size' => $batchSize,
        ];

        // Debug: Log what we're sending
        error_log('[DEBUG] insertMany PHP - First record: ' . json_encode($records[0] ?? null));
        error_log('[DEBUG] insertMany PHP - All records: ' . json_encode($records));

        /** @var mixed $rawResult */
        $rawResult = $this->execute('insertMany', $params); // ejecutar solo una vez

        return is_array($rawResult) ? $rawResult : [];
    }

    /**
     * Actualiza múltiples registros que coincidan con las condiciones WHERE.
     * Utiliza transacciones y consultas optimizadas según la base de datos.
     *
     * @param array<string, mixed> $data Datos a actualizar
     * @param int $maxRecords Límite máximo de registros a actualizar por seguridad (default:
     *                        10000)
     *
     * @throws VersaORMException Si no hay condiciones WHERE o la operación falla
     *
     * @return array<string, mixed> información sobre la operación: rows_affected, etc
     */
    public function updateMany(array $data, int $maxRecords = 10000): array
    {
        if ($data === []) {
            throw new VersaORMException('updateMany requires data to update');
        }

        if ($this->wheres === []) {
            throw new VersaORMException('updateMany requires WHERE conditions to prevent accidental mass updates');
        }

        // Validar nombres de columnas por seguridad
        foreach (array_keys($data) as $column) {
            if (!$this->isSafeIdentifier($column)) {
                throw new VersaORMException(sprintf('Invalid or malicious column name detected: %s', $column));
            }
        }

        // Validar límite máximo por seguridad
        if ($maxRecords <= 0 || $maxRecords > 100000) {
            throw new VersaORMException('Max records limit must be between 1 and 100000');
        }

        $params = [
            'data' => $data,
            'max_records' => $maxRecords,
        ];

        /** @var mixed $rawResult */
        $rawResult = $this->execute('updateMany', $params); // ejecutar solo una vez

        return is_array($rawResult) ? $rawResult : [];
    }

    /**
     * Elimina múltiples registros que coincidan con las condiciones WHERE.
     * Utiliza DELETE optimizado con límites de seguridad.
     *
     * @param int $maxRecords Límite máximo de registros a eliminar por seguridad (default: 10000)
     *
     * @throws VersaORMException Si no hay condiciones WHERE o la operación falla
     *
     * @return array<string, mixed> información sobre la operación: rows_affected, etc
     */
    public function deleteMany(int $maxRecords = 10000): array
    {
        if ($this->wheres === []) {
            throw new VersaORMException('deleteMany requires WHERE conditions to prevent accidental mass deletions');
        }

        // Validar límite máximo por seguridad
        if ($maxRecords <= 0 || $maxRecords > 100000) {
            throw new VersaORMException('Max records limit must be between 1 and 100000');
        }

        $params = [
            'max_records' => $maxRecords,
        ];

        /** @var mixed $rawResult */
        $rawResult = $this->execute('deleteMany', $params); // ejecutar solo una vez

        return is_array($rawResult) ? $rawResult : [];
    }

    /**
     * Upsert (INSERT ... ON DUPLICATE KEY UPDATE) para un solo registro.
     * Inserta un registro nuevo o actualiza el existente basado en claves únicas.
     *
     * @param array<string, mixed> $data Datos del registro
     * @param array<int, string> $uniqueKeys Columnas que determinan duplicados
     * @param array<int, string> $updateColumns Columnas a actualizar en caso de duplicado (opcional)
     *
     * @throws VersaORMException Si los datos son inválidos
     *
     * @return array<string, mixed> Información sobre la operación
     */
    public function upsert(
        array $data,
        array $uniqueKeys,
        array $updateColumns = [],
    ): array {
        if ($data === []) {
            throw new VersaORMException('upsert requires data to insert/update');
        }

        if ($uniqueKeys === []) {
            throw new VersaORMException('upsert requires unique keys to detect duplicates');
        }

        // Validar identificadores por seguridad PRIMERO
        foreach ($uniqueKeys as $key) {
            if (!$this->isSafeIdentifier($key)) {
                throw new VersaORMException('Invalid unique key name detected');
            }
        }

        foreach ($updateColumns as $col) {
            if (!$this->isSafeIdentifier($col)) {
                throw new VersaORMException('Invalid update column name detected');
            }
        }

        // Validar nombres de columnas de data por seguridad
        foreach (array_keys($data) as $column) {
            if (!$this->isSafeIdentifier($column)) {
                throw new VersaORMException(sprintf('Invalid or malicious column name detected: %s', $column));
            }
        }

        // Validar que las claves únicas existen en los datos
        foreach ($uniqueKeys as $key) {
            if (!array_key_exists($key, $data)) {
                throw new VersaORMException(
                    sprintf('Record is missing unique key: %s', $key),
                );
            }
        }

        // FALLBACK: Usar insertOrUpdate() si el binario no soporta upsert nativo
        return $this->upsertFallback($data, $uniqueKeys, $updateColumns);
    }

    /**
     * Método insertOrUpdate() alternativo - Verifica existencia y decide INSERT vs UPDATE.
     *
     * @param array<string, mixed> $data Datos del registro
     * @param array<int, string> $uniqueKeys Columnas para verificar existencia
     * @param array<int, string> $updateColumns Columnas a actualizar en caso de duplicado (opcional)
     *
     * @throws VersaORMException Si los datos son inválidos
     *
     * @return array<string, mixed> Información sobre la operación
     */
    public function insertOrUpdate(
        array $data,
        array $uniqueKeys,
        array $updateColumns = [],
    ): array {
        if ($data === []) {
            throw new VersaORMException('insertOrUpdate requires data');
        }

        if ($uniqueKeys === []) {
            throw new VersaORMException('insertOrUpdate requires unique keys to check existence');
        }

        // Validar identificadores por seguridad
        foreach ($uniqueKeys as $key) {
            if (!$this->isSafeIdentifier($key)) {
                throw new VersaORMException('Invalid unique key name detected');
            }
        }

        foreach ($updateColumns as $col) {
            if (!$this->isSafeIdentifier($col)) {
                throw new VersaORMException('Invalid update column name detected');
            }
        }

        // Validar que las claves únicas existen en los datos
        foreach ($uniqueKeys as $key) {
            if (!array_key_exists($key, $data)) {
                throw new VersaORMException(
                    sprintf('Data is missing unique key: %s', $key),
                );
            }
        }

        // Construir condiciones WHERE para verificar existencia
        $existsQuery = new self($this->orm, $this->table);

        foreach ($uniqueKeys as $key) {
            $existsQuery->where($key, '=', $data[$key]);
        }

        // Verificar si el registro ya existe
        $exists = $existsQuery->exists();

        if ($exists) {
            // Actualizar registro existente
            $updateData = $updateColumns === []
                ? array_diff_key($data, array_flip($uniqueKeys)) // Excluir claves únicas
                : array_intersect_key($data, array_flip($updateColumns)); // Solo columnas especificadas

            if ($updateData === []) {
                return [
                    'status' => 'success',
                    'operation' => 'no_update_needed',
                    'message' => 'Record exists but no columns to update',
                    'unique_keys' => $uniqueKeys,
                ];
            }

            // Crear nueva instancia con las mismas condiciones WHERE
            $updateQuery = new self($this->orm, $this->table);

            foreach ($uniqueKeys as $key) {
                $updateQuery->where($key, '=', $data[$key]);
            }

            $updateQuery->update($updateData);

            return [
                'status' => 'success',
                'operation' => 'updated',
                'rows_affected' => 1,
                'unique_keys' => $uniqueKeys,
                'updated_columns' => array_keys($updateData),
            ];
        }
        // Insertar nuevo registro
        $this->insert($data);

        return [
            'status' => 'success',
            'operation' => 'inserted',
            'rows_affected' => 1,
            'unique_keys' => $uniqueKeys,
        ];
    }

    /**
     * Método save() inteligente - Detecta si es nuevo o existente automáticamente.
     *
     * @param array<string, mixed> $data Datos del registro
     * @param string $primaryKey Clave primaria (default: 'id')
     *
     * @throws VersaORMException Si los datos son inválidos
     *
     * @return array<string, mixed> Información sobre la operación
     */
    public function save(array $data, string $primaryKey = 'id'): array
    {
        if ($data === []) {
            throw new VersaORMException('save requires data');
        }

        if (!$this->isSafeIdentifier($primaryKey)) {
            throw new VersaORMException('Invalid primary key name detected');
        }

        // Si tiene ID, es actualización; si no, es inserción
        if (isset($data[$primaryKey]) && !empty($data[$primaryKey])) {
            // Actualización - separar ID de los datos
            $id = $data[$primaryKey];
            $updateData = $data;
            unset($updateData[$primaryKey]); // Remover ID de los datos a actualizar

            if ($updateData === []) {
                return [
                    'status' => 'success',
                    'operation' => 'no_update_needed',
                    'message' => 'No data to update',
                    'id' => $id,
                ];
            }

            // Crear nueva instancia para la actualización
            $updateQuery = new self($this->orm, $this->table);
            $updateQuery->where($primaryKey, '=', $id)->update($updateData);

            return [
                'status' => 'success',
                'operation' => 'updated',
                'rows_affected' => 1,
                'id' => $id,
                'updated_columns' => array_keys($updateData),
            ];
        }
        // Inserción - crear nuevo registro
        $insertedId = $this->insertGetId($data);

        return [
            'status' => 'success',
            'operation' => 'inserted',
            'rows_affected' => 1,
            'id' => $insertedId,
        ];
    }

    /**
     * Método createOrUpdate() con condiciones personalizadas.
     *
     * @param array<string, mixed> $data Datos del registro
     * @param array<string, mixed> $conditions Condiciones personalizadas para verificar existencia
     * @param array<int, string> $updateColumns Columnas a actualizar en caso de duplicado (opcional)
     *
     * @throws VersaORMException Si los datos son inválidos
     *
     * @return array<string, mixed> Información sobre la operación
     */
    public function createOrUpdate(
        array $data,
        array $conditions,
        array $updateColumns = [],
    ): array {
        if ($data === []) {
            throw new VersaORMException('createOrUpdate requires data');
        }

        if ($conditions === []) {
            throw new VersaORMException('createOrUpdate requires conditions to check existence');
        }

        // Validar nombres de columnas en condiciones
        foreach (array_keys($conditions) as $column) {
            if (!$this->isSafeIdentifier($column)) {
                throw new VersaORMException(sprintf('Invalid column name in conditions: %s', $column));
            }
        }

        foreach ($updateColumns as $col) {
            if (!$this->isSafeIdentifier($col)) {
                throw new VersaORMException('Invalid update column name detected');
            }
        }

        // Construir consulta para verificar existencia
        $existsQuery = new self($this->orm, $this->table);

        foreach ($conditions as $column => $value) {
            $existsQuery->where($column, '=', $value);
        }

        // Verificar si el registro ya existe
        $exists = $existsQuery->exists();

        if ($exists) {
            // Actualizar registro existente
            $updateData = $updateColumns === []
                ? $data // Actualizar todas las columnas
                : array_intersect_key($data, array_flip($updateColumns)); // Solo columnas especificadas

            if ($updateData === []) {
                return [
                    'status' => 'success',
                    'operation' => 'no_update_needed',
                    'message' => 'Record exists but no columns to update',
                    'conditions' => $conditions,
                ];
            }

            // Crear nueva instancia con las mismas condiciones
            $updateQuery = new self($this->orm, $this->table);

            foreach ($conditions as $column => $value) {
                $updateQuery->where($column, '=', $value);
            }

            $updateQuery->update($updateData);

            return [
                'status' => 'success',
                'operation' => 'updated',
                'rows_affected' => 1,
                'conditions' => $conditions,
                'updated_columns' => array_keys($updateData),
            ];
        }
        // Crear nuevo registro (merging conditions with data)
        $insertData = array_merge($data, $conditions);
        $insertedId = $this->insertGetId($insertData);

        return [
            'status' => 'success',
            'operation' => 'created',
            'rows_affected' => 1,
            'id' => $insertedId,
            'conditions' => $conditions,
        ];
    }

    /**
     * Upsert (INSERT ... ON DUPLICATE KEY UPDATE) para múltiples registros.
     * Inserta registros nuevos o actualiza los existentes basado en claves únicas.
     *
     * @param array<int, array<string, mixed>> $records Array de registros
     * @param array<int, string> $uniqueKeys Columnas que determinan duplicados
     * @param array<int, string> $updateColumns Columnas a actualizar en caso de duplicado (opcional)
     * @param int $batchSize Tamaño del lote
     *                       (default: 1000)
     *
     * @throws VersaORMException Si los datos son inválidos
     *
     * @return array<string, mixed> Información sobre la operación
     */
    public function upsertMany(
        array $records,
        array $uniqueKeys,
        array $updateColumns = [],
        int $batchSize = 1000,
    ): array {
        if ($records === []) {
            throw new VersaORMException('upsertMany requires at least one record');
        }

        if ($uniqueKeys === []) {
            throw new VersaORMException('upsertMany requires unique keys to detect duplicates');
        }

        // Validar identificadores por seguridad PRIMERO
        foreach ($uniqueKeys as $key) {
            if (!$this->isSafeIdentifier($key)) {
                throw new VersaORMException('Invalid unique key name detected');
            }
        }

        foreach ($updateColumns as $col) {
            if (!$this->isSafeIdentifier($col)) {
                throw new VersaORMException('Invalid update column name detected');
            }
        }

        // Validar que las claves únicas existen en todos los registros
        foreach ($records as $index => $record) {
            foreach ($uniqueKeys as $key) {
                if (!array_key_exists($key, $record)) {
                    throw new VersaORMException(
                        sprintf('Record at index %d is missing unique key: %s', $index, $key),
                    );
                }
            }
        }

        $params = [
            'records' => $records,
            'unique_keys' => $uniqueKeys,
            'update_columns' => $updateColumns,
            'batch_size' => $batchSize,
        ];

        $this->execute('upsertMany', $params);
        /** @var mixed $rawResult */
        $rawResult = $this->execute('upsertMany', $params);

        return is_array($rawResult) ? $rawResult : [];
    }

    /**
     * REPLACE INTO para MySQL - Compatible solo con MySQL.
     * Reemplaza completamente los registros existentes o inserta nuevos.
     * ADVERTENCIA: REPLACE puede perder datos de columnas no especificadas.
     *
     * @param array<string, mixed> $data Datos del registro
     *
     * @throws VersaORMException Si los datos son inválidos o no es MySQL
     *
     * @return array<string, mixed> Información sobre la operación
     */
    public function replaceInto(array $data): array
    {
        if ($data === []) {
            throw new VersaORMException('replaceInto requires data to replace/insert');
        }

        // Validar nombres de columnas por seguridad
        foreach (array_keys($data) as $column) {
            if (!$this->isSafeIdentifier($column)) {
                throw new VersaORMException(sprintf('Invalid or malicious column name detected: %s', $column));
            }
        }

        // Fallback / emulación por driver
        return $this->replaceIntoFallback($data);
    }

    /**
     * REPLACE INTO múltiples registros para MySQL - Compatible solo con MySQL.
     * Reemplaza completamente los registros existentes o inserta nuevos.
     * ADVERTENCIA: REPLACE puede perder datos de columnas no especificadas.
     *
     * @param array<int, array<string, mixed>> $records Array de registros
     * @param int $batchSize Tamaño del lote (default: 1000)
     *
     * @throws VersaORMException Si los datos son inválidos o no es MySQL
     *
     * @return array<string, mixed> Información sobre la operación
     */
    public function replaceIntoMany(array $records, int $batchSize = 1000): array
    {
        if ($records === []) {
            throw new VersaORMException('replaceIntoMany requires at least one record');
        }

        // Validar tamaño de lote
        if ($batchSize <= 0 || $batchSize > 10000) {
            throw new VersaORMException('Batch size must be between 1 and 10000');
        }

        // Validar que todos los registros tengan la misma estructura
        $firstKeys = array_keys($records[0]);

        foreach ($records as $index => $record) {
            if (!is_array($record) || $record === []) {
                throw new VersaORMException(sprintf('Record at index %d is invalid or empty', $index));
            }

            $currentKeys = array_keys($record);

            if ($currentKeys !== $firstKeys) {
                throw new VersaORMException(
                    sprintf(
                        'Record at index %d has different columns. Expected: [%s], Got: [%s]',
                        $index,
                        implode(', ', $firstKeys),
                        implode(', ', $currentKeys),
                    ),
                );
            }

            // Validar nombres de columnas por seguridad
            foreach ($currentKeys as $column) {
                if (!$this->isSafeIdentifier($column)) {
                    throw new VersaORMException(sprintf('Invalid or malicious column name detected: %s', $column));
                }
            }
        }

        return $this->replaceIntoManyFallback($records, $batchSize);
    }

    /**
     * Activa el modo lazy - las consultas se acumulan pero no se ejecutan hasta collect().
     */
    public function lazy(): self
    {
        $this->isLazy = true;

        return $this;
    }

    /**
     * Ejecuta todas las operaciones lazy acumuladas y devuelve resultados.
     *
     * @return array<int, array<string, mixed>>
     */
    public function collect(): array
    {
        if (!$this->isLazy) {
            // Si no es lazy, ejecutar normalmente
            return $this->get();
        }

        // Agregar la operación actual a las operaciones lazy
        $this->addCurrentOperationToLazy();

        // Optimizar el plan si hay múltiples operaciones
        if (count($this->lazyOperations) > 1) {
            return $this->executeOptimizedPlan();
        }

        // Si solo hay una operación, ejecutar normalmente
        return $this->get();
    }

    /**
     * Encadena múltiples operaciones en modo lazy.
     */
    public function chain(self $otherQuery): self
    {
        if (!$this->isLazy) {
            $this->lazy();
        }

        // Agregar la operación actual
        $this->addCurrentOperationToLazy();

        // Agregar las operaciones del otro query
        $otherQuery->addCurrentOperationToLazy();
        $this->lazyOperations = array_merge($this->lazyOperations, $otherQuery->lazyOperations);

        return $this;
    }

    /**
     * Obtiene información sobre el plan de ejecución sin ejecutarlo.
     *
     * @return array<string, mixed>
     */
    public function explain(): array
    {
        if (!$this->isLazy || $this->lazyOperations === []) {
            $this->addCurrentOperationToLazy();
        }

        // Preparar parámetros para el planificador
        $params = [
            'operations' => $this->lazyOperations,
            'optimize' => [
                'enable_join_optimization' => true,
                'enable_where_combination' => true,
                'enable_subquery_elimination' => true,
                'max_operations_to_combine' => 5,
            ],
        ];

        // Validar que tenemos una instancia válida de VersaORM
        if (!$this->orm instanceof VersaORM) {
            throw new Exception('VersaORM instance is required for explain.');
        }

        // Usar el método execute estándar para que incluya la configuración
        $reflection = new ReflectionClass($this->orm);
        $executeMethod = $reflection->getMethod('execute');
        $executeMethod->setAccessible(true);

        return $executeMethod->invoke($this->orm, 'explain_plan', $params);
    }

    // ========================================
    // FUNCIONALIDADES SQL AVANZADAS - TAREA 7.1
    // ========================================

    /**
     * Aplica una función window a la consulta.
     * Soporta ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, etc.
     *
     * @param string $function Función window (row_number, rank, lag, lead, etc.)
     * @param string $column Columna sobre la que aplicar la función
     * @param array<string, mixed> $args Argumentos específicos de la función
     * @param array<int, string> $partitionBy Columnas para PARTITION BY
     * @param array<int, array<string, mixed>> $orderBy Orden para ORDER BY
     * @param string $alias Alias para el resultado
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la consulta con window function
     */
    public function windowFunction(
        string $function,
        string $column = '*',
        array $args = [],
        array $partitionBy = [],
        array $orderBy = [],
        string $alias = 'window_result',
    ): array {
        $validFunctions = ['row_number', 'rank', 'dense_rank', 'lag', 'lead', 'first_value', 'last_value', 'ntile'];

        if (!in_array(strtolower($function), $validFunctions, true)) {
            throw new VersaORMException(sprintf('Unsupported window function: %s', $function));
        }

        if (!$this->isSafeIdentifier($column) && $column !== '*') {
            throw new VersaORMException(sprintf('Invalid column name: %s', $column));
        }

        if (!$this->isSafeIdentifier($alias)) {
            throw new VersaORMException(sprintf('Invalid alias name: %s', $alias));
        }

        $params = [
            'operation_type' => 'window_function',
            'function' => strtolower($function),
            'column' => $column,
            'args' => $args,
            'partition_by' => $partitionBy,
            'order_by' => $orderBy,
            'alias' => $alias,
            'table' => $this->table,
            'wheres' => $this->wheres,
            'joins' => $this->joins,
            'selects' => $this->selects,
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Crea una consulta con Common Table Expressions (CTEs).
     *
     * @param array<string, array<string, mixed>> $ctes CTEs definidas como ['nombre' => ['query' => 'SQL', 'bindings' => []]]
     * @param string $mainQuery Consulta principal
     * @param array<int, mixed> $mainQueryBindings Bindings para la consulta principal
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la consulta
     */
    public function withCte(array $ctes, string $mainQuery, array $mainQueryBindings = []): array
    {
        if ($ctes === []) {
            throw new VersaORMException('At least one CTE must be provided');
        }

        if (in_array(trim($mainQuery), ['', '0'], true)) {
            throw new VersaORMException('Main query cannot be empty');
        }

        // Validar y preparar CTEs
        $cteDefinitions = [];

        foreach ($ctes as $name => $definition) {
            if (!$this->isSafeIdentifier($name)) {
                throw new VersaORMException(sprintf('Invalid CTE name: %s', $name));
            }
            $rawQuery = $definition['query'] ?? null;
            $queryStr = is_string($rawQuery) ? trim($rawQuery) : '';

            if ($queryStr === '') {
                throw new VersaORMException(sprintf('CTE %s must have a query', $name));
            }

            if (!$this->isSafeRawExpression($queryStr)) {
                throw new VersaORMException(sprintf('Potentially unsafe query in CTE %s', $name));
            }
            $cteDefinitions[] = [
                'name' => $name,
                'query' => $queryStr,
                'bindings' => isset($definition['bindings']) && is_array($definition['bindings']) ? array_values($definition['bindings']) : [],
            ];
        }

        if (!$this->isSafeRawExpression($mainQuery)) {
            throw new VersaORMException('Potentially unsafe main query');
        }

        $params = [
            'operation_type' => 'cte',
            'ctes' => $cteDefinitions,
            'main_query' => $mainQuery,
            'main_query_bindings' => $mainQueryBindings,
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Realiza una operación UNION con otra consulta.
     *
     * @param array<int, array<string, mixed>>|callable|QueryBuilder $queries Consultas a unir
     * @param bool $all Si true, usa UNION ALL
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la operación UNION
     */
    public function union($queries, bool $all = false): array
    {
        if (empty($queries)) {
            throw new VersaORMException('At least one query must be provided for UNION');
        }

        $queryDefinitions = [];

        // Si es un array de queries
        if (is_array($queries)) {
            foreach ($queries as $query) {
                // Requerir explícitamente ambas claves (sql y bindings) para cumplir con la expectativa del test
                if (!is_array($query) || !isset($query['sql'], $query['bindings'])) {
                    throw new VersaORMException('Each UNION query must have sql and bindings keys');
                }

                if (!is_string($query['sql'])) {
                    throw new VersaORMException('Each UNION query must have sql and bindings keys');
                }

                if (!is_array($query['bindings'])) {
                    throw new VersaORMException('Each UNION query must have sql and bindings keys');
                }

                if (!$this->isSafeRawExpression($query['sql'])) {
                    throw new VersaORMException('Potentially unsafe SQL in UNION query');
                }
                $queryDefinitions[] = [
                    'sql' => $query['sql'],
                    'bindings' => array_values($query['bindings']),
                ];
            }
        }
        // Si es un QueryBuilder o callable
        elseif ($queries instanceof self || is_callable($queries)) {
            if (is_callable($queries)) {
                $secondQuery = new self($this->orm, $this->table);
                $queries($secondQuery);
                $queries = $secondQuery;
            }

            $currentSQL = $this->buildSelectSQL();
            $secondSQL = $queries->buildSelectSQL();

            $queryDefinitions = [
                ['sql' => $currentSQL['sql'], 'bindings' => $currentSQL['bindings']],
                ['sql' => $secondSQL['sql'], 'bindings' => $secondSQL['bindings']],
            ];
        } else {
            throw new VersaORMException('Invalid queries parameter for UNION');
        }

        $params = [
            'operation_type' => 'union',
            'queries' => $queryDefinitions,
            'all' => $all,
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Combina la consulta actual con otra usando INTERSECT.
     * Devuelve solo las filas que aparecen en ambas consultas.
     *
     * @param callable|QueryBuilder $query La segunda consulta
     * @param bool $all Si true, usa INTERSECT ALL
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la operación INTERSECT
     */
    public function intersect($query, bool $all = false): array
    {
        if (!$query instanceof self && !is_callable($query)) {
            throw new VersaORMException('INTERSECT query must be a QueryBuilder instance or callable');
        }

        // Si es callable, crear nuevo QueryBuilder
        if (is_callable($query)) {
            $secondQuery = new self($this->orm, $this->table);
            $query($secondQuery);
            $query = $secondQuery;
        }

        // Preparar queries para INTERSECT
        $firstQuerySQL = $this->buildSelectSQL();
        $secondQuerySQL = $query->buildSelectSQL();

        $params = [
            'operation_type' => 'intersect',
            'queries' => [
                ['sql' => $firstQuerySQL['sql'], 'bindings' => $firstQuerySQL['bindings']],
                ['sql' => $secondQuerySQL['sql'], 'bindings' => $secondQuerySQL['bindings']],
            ],
            'all' => $all,
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Combina la consulta actual con otra usando EXCEPT.
     * Devuelve las filas de la primera consulta que no aparecen en la segunda.
     *
     * @param callable|QueryBuilder $query La segunda consulta
     * @param bool $all Si true, usa EXCEPT ALL
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la operación EXCEPT
     */
    public function except($query, bool $all = false): array
    {
        if (!$query instanceof self && !is_callable($query)) {
            throw new VersaORMException('EXCEPT query must be a QueryBuilder instance or callable');
        }

        // Si es callable, crear nuevo QueryBuilder
        if (is_callable($query)) {
            $secondQuery = new self($this->orm, $this->table);
            $query($secondQuery);
            $query = $secondQuery;
        }

        // Preparar queries para EXCEPT
        $firstQuerySQL = $this->buildSelectSQL();
        $secondQuerySQL = $query->buildSelectSQL();

        $params = [
            'operation_type' => 'except',
            'queries' => [
                ['sql' => $firstQuerySQL['sql'], 'bindings' => $firstQuerySQL['bindings']],
                ['sql' => $secondQuerySQL['sql'], 'bindings' => $secondQuerySQL['bindings']],
            ],
            'all' => $all,
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Realiza operaciones JSON específicas del motor de base de datos.
     * Soporta MySQL (->) y PostgreSQL (jsonb) sintaxis.
     *
     * @param string $operation Tipo de operación: extract, contains, search, array_length
     * @param string $column Columna JSON
     * @param string $path Ruta JSON (ej: '$.user.name')
     * @param mixed $value Valor para comparaciones/búsquedas
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la operación JSON
     */
    public function jsonOperation(string $operation, string $column, string $path = '', mixed $value = null): array
    {
        if (!$this->isSafeIdentifier($column)) {
            throw new VersaORMException(sprintf('Invalid column name: %s', $column));
        }

        $validOperations = ['extract', 'contains', 'search', 'array_length', 'type', 'keys'];

        if (!in_array($operation, $validOperations, true)) {
            throw new VersaORMException(sprintf(
                'Invalid JSON operation: %s. Valid operations: %s',
                $operation,
                implode(', ', $validOperations),
            ));
        }

        // Para ciertas operaciones, path es requerido
        if (in_array($operation, ['extract', 'contains', 'search'], true) && ($path === '' || $path === '0')) {
            throw new VersaORMException(sprintf('JSON operation %s requires a path', $operation));
        }

        $params = [
            'operation_type' => 'json_operation',
            'json_operation' => $operation,
            'column' => $column,
            'path' => $path,
            'value' => $value,
            'table' => $this->table,
            'wheres' => $this->wheres,
            'joins' => $this->joins,
            'selects' => $this->selects,
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Operaciones con arrays (específico para PostgreSQL).
     * Permite trabajar con tipos array de PostgreSQL.
     *
     * @param string $operation Tipo de operación: 'contains', 'overlap', 'length', 'append', 'prepend', 'remove'
     * @param string $column Columna array
     * @param mixed $value Valor para la operación
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la operación array
     */
    public function arrayOperations(string $operation, string $column, mixed $value = null): array
    {
        if (!$this->isSafeIdentifier($column)) {
            throw new VersaORMException(sprintf('Invalid column name: %s', $column));
        }

        $validOperations = ['contains', 'overlap', 'length', 'append', 'prepend', 'remove', 'any', 'all'];

        if (!in_array($operation, $validOperations, true)) {
            throw new VersaORMException(sprintf(
                'Invalid array operation: %s. Valid operations: %s',
                $operation,
                implode(', ', $validOperations),
            ));
        }

        // Para operaciones que requieren value
        if (in_array($operation, ['contains', 'overlap', 'append', 'prepend', 'remove', 'any', 'all'], true) && $value === null) {
            throw new VersaORMException(sprintf('Array operation %s requires a value', $operation));
        }

        $params = [
            'operation_type' => 'array_operations',
            'array_operation' => $operation,
            'column' => $column,
            'value' => $value,
            'table' => $this->table,
            'wheres' => $this->wheres,
            'joins' => $this->joins,
            'bindings' => [],
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Aplica hints de optimización específicos del motor de base de datos.
     *
     * @param array<string, mixed> $hints Hints específicos del motor
     *
     * @throws VersaORMException
     */
    public function queryHints(array $hints): self
    {
        if ($hints === []) {
            throw new VersaORMException('Query hints cannot be empty');
        }

        foreach (array_keys($hints) as $hint) {
            // Validar que el hint no contenga SQL malicioso
            if (!$this->isSafeIdentifier($hint) && !$this->isSafeRawExpression($hint)) {
                throw new VersaORMException(sprintf('Potentially unsafe query hint: %s', $hint));
            }
        }

        // Guardar hints para usar en la construcción de la query
        if (!isset($this->lazyOperations)) {
            $this->lazyOperations = [];
        }

        $this->lazyOperations[] = [
            'type' => 'query_hints',
            'hints' => $hints,
        ];

        return $this;
    }

    /**
     * Realiza búsqueda de texto completo usando las capacidades específicas del motor.
     *
     * @param array<int, string> $columns Columnas donde buscar
     * @param string $searchTerm Término a buscar
     * @param array<string, mixed> $options Opciones específicas del motor
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la búsqueda full-text
     */
    public function fullTextSearch(array $columns, string $searchTerm, array $options = []): array
    {
        if ($columns === []) {
            throw new VersaORMException('At least one column must be specified for full-text search');
        }

        if (in_array(trim($searchTerm), ['', '0'], true)) {
            throw new VersaORMException('Search term cannot be empty');
        }

        // Validar columnas
        foreach ($columns as $column) {
            if (!$this->isSafeIdentifier($column)) {
                throw new VersaORMException(sprintf('Invalid column name: %s', $column));
            }
        }

        $params = [
            'operation_type' => 'full_text_search',
            'columns' => $columns,
            'search_term' => $searchTerm,
            'options' => $options,
            'table' => $this->table,
            'wheres' => $this->wheres,
            'joins' => $this->joins,
            'selects' => $this->selects,
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Realiza agregaciones avanzadas como percentiles, median, variance.
     *
     * @param string $type Tipo de agregación: percentile, median, variance, stddev, group_concat
     * @param string $column Columna para la agregación
     * @param array<string, mixed> $options Opciones específicas (ej: percentile => 0.95)
     * @param array<int, string> $groupBy Columnas para agrupar (opcional)
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la agregación
     */
    public function advancedAggregation(string $type, string $column, array $options = [], array $groupBy = [], string $alias = ''): array
    {
        if (!$this->isSafeIdentifier($column)) {
            throw new VersaORMException(sprintf('Invalid column name: %s', $column));
        }

        $validTypes = ['percentile', 'median', 'variance', 'stddev', 'group_concat'];

        if (!in_array($type, $validTypes, true)) {
            throw new VersaORMException(sprintf(
                'Invalid aggregation type: %s. Valid types: %s',
                $type,
                implode(', ', $validTypes),
            ));
        }

        // Validar opciones específicas
        if ($type === 'percentile' && (!isset($options['percentile']) || $options['percentile'] < 0 || $options['percentile'] > 1)) {
            throw new VersaORMException('Percentile must be between 0 and 1');
        }

        $params = [
            'operation_type' => 'advanced_aggregation',
            'aggregation_type' => $type,
            'column' => $column,
            'options' => $options,
            'table' => $this->table,
            'wheres' => $this->wheres,
            'joins' => $this->joins,
            'groupBy' => $groupBy === [] ? $this->groupBy : $groupBy,
            'having' => $this->having,
            'alias' => $alias,
        ];

        // Debug temporal
        // echo "=== DEBUG advancedAggregation ===\n";
        // echo "Type: " . $type . "\n";
        // echo "Column: " . $column . "\n";
        // echo "Options: " . json_encode($options) . "\n";
        // echo "GroupBy: " . json_encode($groupBy) . "\n";
        // echo "Alias: " . $alias . "\n";
        // echo "Params: " . json_encode($params, JSON_PRETTY_PRINT) . "\n";

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Obtiene información sobre las capacidades del motor de base de datos.
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Capacidades del motor
     */
    public function getDriverCapabilities(): array
    {
        $params = [
            'operation_type' => 'get_driver_capabilities',
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Optimiza la consulta actual para el motor de base de datos específico.
     *
     * @param array<string, mixed> $options Opciones de optimización
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Información de optimización y consulta optimizada
     */
    public function optimizeQuery(array $options = []): array
    {
        if ($options === []) {
            throw new VersaORMException('Query cannot be empty');
        }

        $querySQL = $this->buildSelectSQL();

        $params = [
            'operation_type' => 'optimize_query',
            'query' => $querySQL['sql'],
            'bindings' => $querySQL['bindings'],
            'options' => $options,
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Obtiene los límites del motor de base de datos.
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Límites del motor
     */
    public function getDriverLimits(): array
    {
        $params = [
            'operation_type' => 'get_driver_limits',
        ];

        return $this->executeAdvancedSQL($params);
    }

    /**
     * Valida si un nombre de tabla o columna es seguro.
     */
    private function isSafeIdentifier(string $identifier): bool
    {
        // Permitir asterisco para SELECT *
        if ($identifier === '*') {
            return true;
        }

        // Manejar alias (ej: users.name as author_name)
        $parts = preg_split('/\s+as\s+/i', $identifier);

        if ($parts === false) {
            return false;
        }
        $mainIdentifier = $parts[0];
        $alias = $parts[1] ?? null;

        if ($alias !== null && !$this->isValidDatabaseIdentifier($alias)) {
            return false; // Alias inválido
        }

        // Permitir funciones SQL comunes (COUNT, SUM, AVG, MAX, MIN, etc.)
        if ($this->isSQLFunction($mainIdentifier)) {
            return true;
        }

        // Manejar notación table.column
        if (str_contains($mainIdentifier, '.')) {
            [$table, $column] = explode('.', $mainIdentifier, 2);

            // Permitir patrones como "table.*" que son válidos en SQL
            if ($column === '*') {
                return $this->isValidDatabaseIdentifier($table);
            }

            return $this->isValidDatabaseIdentifier($table) && $this->isValidDatabaseIdentifier($column);
        }

        return $this->isValidDatabaseIdentifier($mainIdentifier);
    }

    /**
     * Valida un identificador de base de datos individual.
     */
    private function isValidDatabaseIdentifier(string $identifier): bool
    {
        // Expresión regular para validar identificadores:
        // - Debe empezar con una letra o guion bajo.
        // - Seguido de letras, números o guiones bajos.
        if (in_array(preg_match('/^[a-zA-Z_]\w*$/', $identifier), [0, false], true)) {
            return false;
        }

        // Comprobar la existencia de patrones maliciosos
        return !(str_contains($identifier, '--') || str_contains($identifier, '/*') || str_contains($identifier, ';'));
    }

    /**
     * Verifica si un identificador es una función SQL válida.
     */
    private function isSQLFunction(string $identifier): bool
    {
        // Lista de funciones SQL comunes permitidas
        $allowedFunctions = [
            'COUNT',
            'SUM',
            'AVG',
            'MAX',
            'MIN',
            'UPPER',
            'LOWER',
            'LENGTH',
            'SUBSTRING',
            'CONCAT',
            'COALESCE',
            'IFNULL',
            'NULLIF',
            'ABS',
            'ROUND',
            'CEIL',
            'FLOOR',
            'NOW',
            'CURDATE',
            'CURTIME',
            'DATE',
            'YEAR',
            'MONTH',
            'DAY',
            'HOUR',
            'MINUTE',
            'SECOND',
            'TRIM',
            'LTRIM',
            'RTRIM',
            'REPLACE',
            'DISTINCT',
        ];

        // Verificar si es una función SQL con paréntesis
        if (preg_match('/^([A-Z_]+)\s*\((.*)\)$/i', $identifier, $matches)) {
            $functionName = strtoupper($matches[1]);
            $functionArgs = $matches[2];

            // Verificar si la función está en la lista permitida
            if (!in_array($functionName, $allowedFunctions, true)) {
                return false;
            }

            // Validar argumentos básicos (permitir *, columnas simples, números y strings)
            if ($functionArgs === '*') {
                return true; // COUNT(*), etc.
            }

            // Permitir argumentos simples como column names, números, strings
            // Verificar que no contenga patrones maliciosos
            if (preg_match('/^[a-zA-Z0-9_.,\s\'"]+$/', $functionArgs) === 1 && (!str_contains($functionArgs, '--')
            && !str_contains($functionArgs, '/*')
            && !str_contains($functionArgs, ';'))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Valida si una expresión SQL raw es relativamente segura.
     * NOTA: Esta es una validación básica, no una garantía completa de seguridad.
     */
    private function isSafeRawExpression(string $expression): bool
    {
        // Lista de patrones peligrosos comunes
        $dangerousPatterns = [
            '/--/',                  // Comentarios SQL
            '/\/\*/',               // Comentarios de bloque
            '/;\s*(?:drop|delete|insert|update|create|alter|truncate)/i', // Comandos peligrosos después de ;
            '/union\s+select/i',     // UNION attacks
            '/\bexec\s*\(/i',       // Ejecución de funciones
            '/\bsp_/i',            // Stored procedures
            '/xp_/i',              // Extended stored procedures
            '/into\s+outfile/i',   // Escritura de archivos
            '/load_file/i',        // Lectura de archivos
            '/benchmark/i',        // Ataques de timing
            '/sleep/i',            // Ataques de timing
            '/waitfor/i',          // Ataques de timing
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $expression)) {
                return false;
            }
        }

        // Verificar que la expresión no sea demasiado compleja
        // (como medida básica contra inyecciones complejas)
        if (strlen($expression) > 500) {
            return false;
        }

        // Contar paréntesis balanceados
        $openParens = substr_count($expression, '(');
        $closeParens = substr_count($expression, ')');

        return $openParens === $closeParens;
    }

    /**
     * Agrega entrada tipada al array de wheres para mantener shape estática.
     *
     * @param 'and'|'or' $type
     */
    private function addWhereEntry(string $column, string $operator, mixed $value, string $type): void
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value,
            'type' => $type === 'or' ? 'or' : 'and',
        ];
    }

    /**
     * Construye una subconsulta desde un callback o QueryBuilder.
     *
     * @param Closure|QueryBuilder $callback
     *
     * @return array<string, mixed>
     */
    private function buildSubQuery($callback): array
    {
        if ($callback instanceof Closure) {
            // Crear una nueva instancia de QueryBuilder para la subconsulta
            $subQueryBuilder = new self($this->orm, $this->table, $this->modelClass);
            $callback($subQueryBuilder);

            // Construir el payload de la subconsulta
            return [
                'type' => 'subquery',
                'table' => $subQueryBuilder->getTable(),
                'select' => $subQueryBuilder->selects !== [] ? $subQueryBuilder->selects : ['*'],
                'where' => $subQueryBuilder->processWheres(),
                'joins' => $subQueryBuilder->joins,
                'orderBy' => $subQueryBuilder->orderBy !== null && $subQueryBuilder->orderBy !== [] ? [$subQueryBuilder->orderBy] : [],
                'groupBy' => $subQueryBuilder->groupBy,
                'having' => $subQueryBuilder->having,
                'limit' => $subQueryBuilder->limit,
                'offset' => $subQueryBuilder->offset,
            ];
        }

        if ($callback instanceof self) {
            // Si ya es un QueryBuilder, usar directamente
            return [
                'type' => 'subquery',
                'table' => $callback->getTable(),
                'select' => $callback->selects !== [] ? $callback->selects : ['*'],
                'where' => $callback->processWheres(),
                'joins' => $callback->joins,
                'orderBy' => $callback->orderBy !== null && $callback->orderBy !== [] ? [$callback->orderBy] : [],
                'groupBy' => $callback->groupBy,
                'having' => $callback->having,
                'limit' => $callback->limit,
                'offset' => $callback->offset,
            ];
        }

        throw new VersaORMException('Subquery callback must be a Closure or QueryBuilder instance');
    }

    /**
     * Converts a subquery (QueryBuilder or Closure) to SQL and extracts parameters.
     *
     * @param Closure|QueryBuilder $subquery
     *
     * @return array{sql: string, bindings: array<mixed>}
     */
    private function convertSubqueryToSql($subquery): array
    {
        if ($subquery instanceof self) {
            // If it's already a QueryBuilder, build the SQL and extract bindings
            return $this->buildSubquerySqlAndBindings($subquery);
        }

        if ($subquery instanceof Closure) {
            // Create a new QueryBuilder instance for the closure
            $subQueryBuilder = new self($this->orm, $this->table, $this->modelClass);
            $subquery($subQueryBuilder);

            return $this->buildSubquerySqlAndBindings($subQueryBuilder);
        }

        throw new VersaORMException('Subquery must be a Closure or QueryBuilder instance');
    }

    /**
     * Builds SQL string and extracts bindings from a QueryBuilder instance.
     * This properly handles parameter binding for the Rust engine.
     *
     * @return array{sql: string, bindings: array<mixed>}
     */
    private function buildSubquerySqlAndBindings(self $builder): array
    {
        $sql = 'SELECT ';
        $bindings = [];

        // Handle SELECT columns
        if ($builder->selects !== []) {
            $selectColumns = [];

            foreach ($builder->selects as $select) {
                if (is_string($select)) {
                    $selectColumns[] = $select;
                } elseif (is_array($select) && isset($select['expression'])) {
                    $selectColumns[] = $select['expression'];
                }
            }
            $sql .= implode(', ', $selectColumns);
        } else {
            $sql .= '*';
        }

        // FROM clause
        $sql .= ' FROM ' . $builder->table;

        // WHERE clauses - Extract bindings properly
        if ($builder->wheres !== []) {
            $wheresParts = [];

            foreach ($builder->wheres as $where) {
                if (is_array($where) && isset($where['column'], $where['operator'], $where['value'])) {
                    $wheresParts[] = $where['column'] . ' ' . $where['operator'] . ' ?';
                    $bindings[] = $where['value'];
                }
            }

            if ($wheresParts !== []) {
                $sql .= ' WHERE ' . implode(' AND ', $wheresParts);
            }
        }

        // GROUP BY
        if ($builder->groupBy !== [] && is_array($builder->groupBy)) {
            $sql .= ' GROUP BY ' . implode(', ', $builder->groupBy);
        }

        // HAVING
        if ($builder->having !== [] && is_array($builder->having)) {
            $havingParts = [];

            foreach ($builder->having as $having) {
                if (is_array($having) && isset($having['column'], $having['operator'], $having['value'])) {
                    $havingParts[] = $having['column'] . ' ' . $having['operator'] . ' ?';
                    $bindings[] = $having['value'];
                }
            }

            if ($havingParts !== []) {
                $sql .= ' HAVING ' . implode(' AND ', $havingParts);
            }
        }

        // ORDER BY
        if (
            $builder->orderBy && is_array($builder->orderBy)
            && isset($builder->orderBy['column'], $builder->orderBy['direction'])
            && is_string($builder->orderBy['column']) && is_string($builder->orderBy['direction'])
        ) {
            $sql .= ' ORDER BY ' . $builder->orderBy['column'] . ' ' . $builder->orderBy['direction'];
        }

        // LIMIT
        if ($builder->limit !== null && $builder->limit !== 0) {
            $sql .= ' LIMIT ' . $builder->limit;
        }

        return [
            'sql' => $sql,
            'bindings' => $bindings,
        ];
    }

    /**
     * Procesa las cláusulas WHERE y convierte las cláusulas RAW en SQL comprendido.
     *
     * @return array<int, array<string, mixed>>
     */
    private function processWheres(): array
    {
        // Esta función ahora es más simple.
        // Simplemente devuelve el array de wheres.
        // La lógica de procesamiento se ha movido a donde se construye el payload,
        // o se ha determinado que no es necesaria si la estructura es correcta desde el principio.
        $result = [];

        foreach ($this->wheres as $where) {
            if (is_array($where)) {
                $result[] = $where;
            }
        }

        return $result;
    }

    /**
     * Ejecuta la consulta usando la instancia de VersaORM.
     *
     * @param array<string, mixed>|null $data
     *
     * @return mixed
     */
    private function execute(string $method, ?array $data = null)
    {
        if (!$this->orm instanceof VersaORM) {
            throw new Exception('VersaORM instance is required for QueryBuilder execution.');
        }

        $params = $this->buildPayload($method, $data);

        // Determinar la acción principal. Para operaciones de escritura, es el método mismo.
        // Para lectura, es 'query'.
        $batchMethods = ['insertMany', 'updateMany', 'deleteMany', 'upsertMany'];
        $writeMethods = ['insert', 'insertGetId', 'update', 'delete', 'upsert'];

        if (in_array($method, $batchMethods, true)) {
            // Ahora enviamos operaciones batch como acciones dedicadas (insertMany, updateMany, etc.)
            $action = $method;
            // El motor PDO ignora 'method' para acciones directas; mantenerlo no afecta.
        } elseif (in_array($method, $writeMethods, true)) {
            // Las operaciones de escritura normales van como su propio método
            $action = $method;
        } else {
            // Las operaciones de lectura van como 'query'
            $action = 'query';
            $params['method'] = $method;
        }

        // Usar el método público executeQuery en lugar de reflexión
        return $this->orm->executeQuery($action, $params);
    }

    /**
     * @param array<string, mixed>|null $data
     *
     * @return array<string, mixed>
     */
    private function buildPayload(string $method, ?array $data = null): array
    {
        // Asegurar que selects nunca esté vacío - usar ['*'] por defecto
        $selects = $this->selects === [] ? ['*'] : $this->selects;

        // Preparar orderBy como array de objetos para Rust
        $orderBy = [];

        if ($this->orderBy !== null) {
            $orderBy = [$this->orderBy];
        }

        $params = [
            'table' => $this->table,
            'select' => $selects,
            'joins' => $this->joins,
            'where' => $this->processWheres(),
            'orderBy' => $orderBy,
            'groupBy' => $this->groupBy,
            'having' => $this->having,
            'limit' => $this->limit,
            'offset' => $this->offset,
            'with' => $this->with,
            'method' => $method,
        ];

        if ($data !== null) {
            // For batch operations, params go directly at the root
            $batchMethods = ['insertMany', 'updateMany', 'deleteMany', 'upsertMany'];

            if (in_array($method, $batchMethods, true)) {
                // Merge batch parameters directly into params rather than nesting under 'data'
                $params = array_merge($params, $data);
                // Debug: Log the final merged params
                error_log('[DEBUG] buildPayload - Final merged params for ' . $method . ': ' . json_encode($params));
            } else {
                // For normal operations, keep existing behavior
                $params['data'] = $data;
            }
        }

        return $params;
    }

    /**
     * Implementación fallback del upsert usando operaciones INSERT/UPDATE existentes.
     *
     * @param array<string, mixed> $data Datos del registro
     * @param array<int, string> $uniqueKeys Columnas que determinan duplicados
     * @param array<int, string> $updateColumns Columnas a actualizar en caso de duplicado
     *
     * @return array<string, mixed> Información sobre la operación
     */
    private function upsertFallback(
        array $data,
        array $uniqueKeys,
        array $updateColumns = [],
    ): array {
        // Construir condiciones WHERE para verificar existencia
        $existsQuery = new self($this->orm, $this->table);

        foreach ($uniqueKeys as $key) {
            $existsQuery->where($key, '=', $data[$key]);
        }

        // Verificar si el registro ya existe
        $exists = $existsQuery->exists();

        if ($exists) {
            // Actualizar registro existente
            $updateData = $updateColumns === []
                ? array_diff_key($data, array_flip($uniqueKeys)) // Excluir claves únicas
                : array_intersect_key($data, array_flip($updateColumns)); // Solo columnas especificadas

            if ($updateData === []) {
                return [
                    'status' => 'success',
                    'operation' => 'no_update_needed',
                    'rows_affected' => 0,
                    'unique_keys' => $uniqueKeys,
                    'table' => $this->table,
                ];
            }

            // Crear nueva instancia con las mismas condiciones WHERE
            $updateQuery = new self($this->orm, $this->table);

            foreach ($uniqueKeys as $key) {
                $updateQuery->where($key, '=', $data[$key]);
            }

            $updateQuery->update($updateData);

            return [
                'status' => 'success',
                'operation' => 'updated',
                'rows_affected' => 1,
                'unique_keys' => $uniqueKeys,
                'table' => $this->table,
                'update_columns' => $updateColumns, // Siempre incluir, será vacío si no se especificaron
            ];
        }
        // Insertar nuevo registro
        $this->insert($data);

        return [
            'status' => 'success',
            'operation' => 'inserted',
            'rows_affected' => 1,
            'unique_keys' => $uniqueKeys,
            'table' => $this->table,
        ];
    }

    /**
     * Implementación fallback para REPLACE INTO usando SQL raw.
     *
     * @param array<string, mixed> $data Datos del registro
     *
     * @return array<string, mixed> Información sobre la operación
     */
    private function replaceIntoFallback(array $data): array
    {
        // Ejecutar usando raw SQL
        if (!$this->orm instanceof VersaORM) {
            throw new VersaORMException('VersaORM instance is required for replaceInto');
        }

        $config = $this->orm->getConfig();
        $driver = strtolower((string) ($config['driver'] ?? $config['database_type'] ?? 'mysql'));

        // MySQL/MariaDB: usar REPLACE INTO nativo
        if ($driver === 'mysql' || $driver === 'mariadb') {
            // Construir la consulta REPLACE INTO manualmente
            $columns = array_keys($data);
            $placeholders = array_fill(0, count($data), '?');

            $sql = sprintf(
                'REPLACE INTO `%s` (`%s`) VALUES (%s)',
                $this->table,
                implode('`, `', $columns),
                implode(', ', $placeholders),
            );

            $this->orm->exec($sql, array_values($data));

            return [
                'status' => 'success',
                'operation' => 'replaced',
                'rows_affected' => 1,
                'table' => $this->table,
            ];
        }

        // Otros drivers (PostgreSQL, SQLite): emular como UPSERT por PK/únicas, sin DELETE
        // 1) Detectar claves para upsert (PK preferente; si no, índice único disponible en los datos)
        [$uniqueKeys, $updateColumns] = $this->detectUpsertKeysForReplace($data);

        // 2) Si no hay claves únicas detectadas en los datos, hacer un INSERT estándar
        if (empty($uniqueKeys)) {
            // Reutilizar ruta de inserción
            $insertParams = [
                'method' => 'insert',
                'table' => $this->table,
                'data' => $data,
            ];
            // Ejecutar a través del mismo mecanismo que insert() usa internamente
            $result = $this->execute('insert', $data);

            return is_array($result) ? $result : ['status' => 'success', 'operation' => 'inserted', 'rows_affected' => 1, 'table' => $this->table];
        }

        // 3) Delegar a upsert con updateColumns = todas menos las claves
        $result = $this->upsert($data, $uniqueKeys, $updateColumns);

        // Normalizar respuesta para compatibilidad con tests de "replace"
        if (!is_array($result)) {
            $result = [];
        }
        $result['table'] = $this->table;
        $result['status'] ??= 'success';
        $result['operation'] = 'replaced';
        $result['rows_affected'] ??= 1;

        return $result;
    }

    /**
     * Implementación fallback para REPLACE INTO múltiple usando SQL raw.
     *
     * @param array<int, array<string, mixed>> $records Array de registros
     * @param int $batchSize Tamaño del lote
     *
     * @return array<string, mixed> Información sobre la operación
     */
    private function replaceIntoManyFallback(array $records, int $batchSize): array
    {
        if (!$this->orm instanceof VersaORM) {
            throw new VersaORMException('VersaORM instance is required for replaceIntoMany');
        }

        $config = $this->orm->getConfig();
        $driver = strtolower((string) ($config['driver'] ?? $config['database_type'] ?? 'mysql'));

        // MySQL/MariaDB: usar REPLACE INTO en lotes
        if ($driver === 'mysql' || $driver === 'mariadb') {
            $totalReplaced = 0;
            $batchesProcessed = 0;
            $effectiveBatchSize = max(1, $batchSize); // Asegurar que sea al menos 1
            $recordBatches = array_chunk($records, $effectiveBatchSize);

            foreach ($recordBatches as $batch) {
                // Construir SQL para este lote
                $columns = array_keys($batch[0]);
                $valueGroups = [];
                $allValues = [];

                foreach ($batch as $record) {
                    $placeholders = array_fill(0, count($record), '?');
                    $valueGroups[] = '(' . implode(', ', $placeholders) . ')';
                    $allValues = array_merge($allValues, array_values($record));
                }

                $sql = sprintf(
                    'REPLACE INTO `%s` (`%s`) VALUES %s',
                    $this->table,
                    implode('`, `', $columns),
                    implode(', ', $valueGroups),
                );

                // Ejecutar el lote
                $this->orm->exec($sql, $allValues);
                $totalReplaced += count($batch);
                ++$batchesProcessed;
            }

            return [
                'status' => 'success',
                'total_replaced' => $totalReplaced,
                'batches_processed' => $batchesProcessed,
                'batch_size' => $batchSize,
                'total_records' => count($records),
                'table' => $this->table,
            ];
        }

        // Otros drivers (PostgreSQL, SQLite): emular con upsertMany por PK/índices únicos
        [$uniqueKeys, $updateColumns] = $this->detectUpsertKeysForReplace($records[0]);

        if (empty($uniqueKeys)) {
            // Sin claves únicas detectadas en los datos: repetir insertMany simple
            // Reutilizar generate/execute de upsertMany espera unique_keys, así que haremos inserciones individuales
            $inserted = 0;

            foreach ($records as $rec) {
                $this->execute('insert', $rec);
                ++$inserted;
            }

            return [
                'status' => 'success',
                'total_replaced' => $inserted,
                'batches_processed' => 1,
                'batch_size' => $batchSize,
                'total_records' => count($records),
                'table' => $this->table,
            ];
        }

        // Ejecutar la operación con upsertMany pero devolver métrica tipo REPLACE
        $this->upsertMany($records, $uniqueKeys, $updateColumns);
        $total = count($records);
        $batchesProcessed = (int) ceil($total / max(1, $batchSize));

        return [
            'status' => 'success',
            'total_replaced' => $total,
            'batches_processed' => $batchesProcessed,
            'batch_size' => $batchSize,
            'total_records' => $total,
            'table' => $this->table,
        ];
    }

    /**
     * Detecta claves únicas apropiadas para emular REPLACE (PK preferente) y columnas a actualizar.
     * Devuelve [uniqueKeys, updateColumns]. Si no encuentra claves presentes en los datos, uniqueKeys = [].
     *
     * @param array<string,mixed> $data
     *
     * @return array{0:array<int,string>,1:array<int,string>}
     */
    private function detectUpsertKeysForReplace(array $data): array
    {
        $keysInData = array_keys($data);
        $keysInData = array_values(array_filter($keysInData, fn ($k): bool => $this->isSafeIdentifier($k)));

        $pk = [];

        try {
            $cols = $this->orm instanceof VersaORM ? (array) $this->orm->schema('columns', $this->table) : [];

            foreach ($cols as $col) {
                $name = (string) ($col['column_name'] ?? $col['name'] ?? '');
                $isPk = false;

                if (isset($col['is_primary_key'])) {
                    $isPk = (bool) $col['is_primary_key'];
                } elseif (isset($col['extra']) && strtolower((string) $col['extra']) === 'primary_key') {
                    $isPk = true;
                } elseif (isset($col['key']) && strtoupper((string) $col['key']) === 'PRI') {
                    $isPk = true;
                }

                if ($isPk && $name !== '' && in_array($name, $keysInData, true)) {
                    $pk[] = $name;
                }
            }
        } catch (Throwable) {
            // Silencioso: usar heurísticas si falla
        }

        // Si no detectamos PK presentes en los datos, intentar con índices únicos
        if ($pk === []) {
            try {
                $idx = $this->orm instanceof VersaORM ? (array) $this->orm->schema('indexes', $this->table) : [];

                foreach ($idx as $ix) {
                    $unique = (bool) ($ix['unique'] ?? false);
                    $cols = (array) ($ix['columns'] ?? ($ix['column'] ?? []));

                    if (!is_array($cols)) {
                        $cols = [$cols];
                    }
                    $cols = array_values(array_filter(array_map('strval', $cols)));

                    if ($unique && $cols !== [] && array_diff($cols, $keysInData) === []) {
                        $pk = $cols;
                        break;
                    }
                }
            } catch (Throwable) {
                // Ignorar
            }
        }

        // Heurística final: si hay 'id' en los datos, úsalo como clave
        if ($pk === [] && in_array('id', $keysInData, true)) {
            $pk = ['id'];
        }

        $updateColumns = array_values(array_diff($keysInData, $pk));

        return [$pk, $updateColumns];
    }

    /**
     * Agrega la operación actual al conjunto de operaciones lazy.
     */
    private function addCurrentOperationToLazy(): void
    {
        $operation = [
            'operation_type' => 'SELECT',
            'table' => $this->table,
            'columns' => $this->selects === [] ? ['*'] : $this->selects,
            'conditions' => $this->convertWheresToConditions(),
            'join_conditions' => $this->convertJoinsToConditions(),
            'ordering' => $this->convertOrderByToArray(),
            'grouping' => $this->groupBy,
            'having' => $this->convertHavingToConditions(),
            'limit' => $this->limit,
            'offset' => $this->offset,
            'relations' => $this->with,
        ];

        $this->lazyOperations[] = $operation;
    }

    /**
     * Convierte las condiciones WHERE al formato del planificador.
     *
     * @return array<int, array<string, mixed>>
     */
    private function convertWheresToConditions(): array
    {
        $conditions = [];

        foreach ($this->wheres as $where) {
            $conditions[] = [
                'column' => $where['column'] ?? '',
                'operator' => $where['operator'] ?? '=',
                'value' => $where['value'] ?? null,
                // Los WHERE almacenan 'type' ('and'|'or'); mapearlo a 'AND'/'OR'
                'connector' => isset($where['type']) && $where['type'] === 'or' ? 'OR' : 'AND',
            ];
        }

        return $conditions;
    }

    /**
     * Convierte los JOINs al formato del planificador.
     *
     * @return array<int, array<string, mixed>>
     */
    private function convertJoinsToConditions(): array
    {
        $joinConditions = [];

        foreach ($this->joins as $join) {
            $local = $join['first_col'] ?? '';
            $foreign = $join['second_col'] ?? '';
            $op = $join['operator'] ?? '=';

            if (isset($join['conditions'][0]) && is_array($join['conditions'][0])) {
                $c = $join['conditions'][0];
                $local = isset($c['local']) ? (string) $c['local'] : $local;
                $foreign = isset($c['foreign']) ? (string) $c['foreign'] : $foreign;
                $op = isset($c['operator']) ? (string) $c['operator'] : $op;
            }
            $joinConditions[] = [
                'table' => $join['table'] ?? '',
                'join_type' => strtoupper($join['type'] ?? 'INNER'),
                'local_column' => $local,
                'foreign_column' => $foreign,
                'operator' => $op,
            ];
        }

        return $joinConditions;
    }

    /**
     * Convierte ORDER BY al formato del planificador.
     *
     * @return array<int, array<string, mixed>>
     */
    private function convertOrderByToArray(): array
    {
        if ($this->orderBy === null) {
            return [];
        }

        // Verificar si es una expresión raw
        if (isset($this->orderBy['type']) && $this->orderBy['type'] === 'raw') {
            return [
                [
                    'column' => $this->orderBy['expression'] ?? '',
                    'direction' => 'ASC', // Raw expressions no tienen dirección específica
                ],
            ];
        }

        // Orden normal con columna y dirección
        $direction = $this->orderBy['direction'] ?? 'ASC';

        if (is_array($direction)) {
            $direction = 'ASC'; // Fallback si es array por alguna razón
        }

        return [
            [
                'column' => $this->orderBy['column'] ?? '',
                'direction' => strtoupper((string) $direction),
            ],
        ];
    }

    /**
     * Convierte las condiciones HAVING al formato del planificador.
     *
     * @return array<int, array<string, mixed>>
     */
    private function convertHavingToConditions(): array
    {
        $conditions = [];

        foreach ($this->having as $having) {
            $conditions[] = [
                'column' => $having['column'] ?? '',
                'operator' => $having['operator'] ?? '=',
                'value' => $having['value'] ?? null,
                'connector' => $having['connector'] ?? 'AND',
            ];
        }

        return $conditions;
    }

    /**
     * Ejecuta el plan optimizado usando el planificador de consultas de Rust.
     *
     * @return array<int, array<string, mixed>>
     */
    private function executeOptimizedPlan(): array
    {
        if (!$this->orm instanceof VersaORM) {
            throw new Exception('VersaORM instance is required for lazy execution.');
        }

        // Preparar payload para el planificador de consultas
        $params = [
            'action' => 'query_plan',
            'operations' => $this->lazyOperations,
            'optimize' => [
                'enable_join_optimization' => true,
                'enable_where_combination' => true,
                'enable_subquery_elimination' => true,
                'max_operations_to_combine' => 5,
            ],
        ];

        // Ejecutar usando reflexión para acceder al método execute privado
        $reflection = new ReflectionClass($this->orm);
        $executeMethod = $reflection->getMethod('execute');
        $executeMethod->setAccessible(true);

        $result = $executeMethod->invoke($this->orm, 'query_plan', $params);

        // Limpiar operaciones lazy después de la ejecución
        $this->lazyOperations = [];
        $this->isLazy = false;

        return $result;
    }

    /**
     * Construye la SQL SELECT para usar en intersect, except y union.
     *
     * @return array<string, mixed> Array con 'sql' y 'bindings'
     */
    private function buildSelectSQL(): array
    {
        $sql = 'SELECT ';

        // SELECT
        if ($this->selects === []) {
            $sql .= '*';
        } else {
            /** @var list<string> $selectParts */
            $selectParts = [];

            foreach ($this->selects as $select) {
                if (is_string($select)) {
                    $selectParts[] = $select;
                    continue;
                }

                if (is_array($select) && isset($select['type'])) {
                    $type = $select['type'];

                    if ($type === 'raw' && isset($select['expression']) && is_string($select['expression'])) {
                        $selectParts[] = $select['expression'];
                        continue;
                    }

                    if (($type === 'sub' || $type === 'subquery') && isset($select['query'], $select['alias']) && is_string($select['query']) && is_string($select['alias']) && $select['alias'] !== '') {
                        $selectParts[] = sprintf('(%s) AS %s', $select['query'], $select['alias']);
                        continue;
                    }

                    if (isset($select['column']) && is_string($select['column'])) {
                        $selectParts[] = $select['column'];
                    }
                }
            }

            if ($selectParts === []) {
                $selectParts[] = '*';
            }
            $sql .= implode(', ', $selectParts);
        }

        // FROM
        $sql .= ' FROM ' . $this->table;

        // WHERE
        $bindings = [];

        if ($this->wheres !== []) {
            $sql .= ' WHERE ';
            $whereParts = [];

            foreach ($this->wheres as $where) {
                if (isset($where['sql'], $where['bindings']) && is_string($where['sql']) && is_array($where['bindings'])) {
                    $whereParts[] = $where['sql'];
                    /** @var list<mixed> $wb */
                    $wb = array_values($where['bindings']);
                    $bindings = array_merge($bindings, $wb);
                    continue;
                }
                $operator = isset($where['operator']) && is_string($where['operator']) ? $where['operator'] : '=';
                $col = isset($where['column']) && is_string($where['column']) ? $where['column'] : '';
                $whereParts[] = sprintf('%s %s ?', $col, $operator);
                $bindings[] = $where['value'] ?? null;
            }
            $sql .= implode(' AND ', $whereParts);
        }

        return ['sql' => $sql, 'bindings' => $bindings];
    }

    /**
     * Ejecuta una operación SQL avanzada utilizando el handler de Rust.
     *
     * @param array<string, mixed> $params Parámetros de la operación
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed> Resultados de la operación
     */
    private function executeAdvancedSQL(array $params): array
    {
        // echo "=== DEBUG executeAdvancedSQL (Private) ===\n";
        // echo "Params: " . json_encode($params, JSON_PRETTY_PRINT) . "\n";

        error_log('[DEBUG] Executing advanced SQL operation from QueryBuilder...');

        if (!$this->orm instanceof VersaORM) {
            throw new Exception('VersaORM instance is required for advanced SQL execution.');
        }

        // Usar reflexión para acceder al método execute de VersaORM
        $reflection = new ReflectionClass($this->orm);
        $executeMethod = $reflection->getMethod('execute');
        $executeMethod->setAccessible(true);

        // Las operaciones avanzadas van como acción 'advanced_sql'
        $result = $executeMethod->invoke($this->orm, 'advanced_sql', $params);

        // Si el resultado es un array con 'rows', extraer solo las filas
        if (is_array($result) && isset($result['rows'])) {
            return $result['rows'];
        }

        return $result;
    }
}
