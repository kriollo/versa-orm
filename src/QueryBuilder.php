<?php

declare(strict_types=1);

namespace VersaORM;

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
 * @package VersaORM
 * @version 1.0.0
 * @author VersaORM Team
 * @license MIT
 */
class QueryBuilder
{
    /** @var VersaORM|array<string, mixed>|null */
    private $orm; // Puede ser array (config) o instancia de VersaORM
    private string $table;
    /** @var array<int, string> */
    private array $selects = [];
    /** @var array<int, mixed> */
    private array $wheres = [];
    /** @var array<int, mixed> */
    private array $joins = [];
    /** @var array<string, string>|null */
    private ?array $orderBy = null;
    private ?int $limit = null;
    private ?int $offset = null;
    /** @var array<int, string> */
    private array $groupBy = [];
    /** @var array<int, mixed> */
    private array $having = [];
    /** @var array<int, array<string, mixed>> */
    private array $with = [];
    private ?string $modelClass = null;

    /**
     * @param VersaORM|array<string, mixed>|null $orm
     * @param string $table
     * @param string|null $modelClass
     */
    public function __construct($orm, string $table, ?string $modelClass = null)
    {
        $this->orm = $orm;
        $this->table = $table;
        $this->modelClass = $modelClass;
    }

    /**
     * Especifica las columnas a seleccionar.
     *
     * @param array<int, string> $columns
     * @return self
     */
    public function select(array $columns = ['*']): self
    {
        if (empty($columns)) {
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
     * Valida si un nombre de tabla o columna es seguro.
     *
     * @param string $identifier
     * @return bool
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
            return $this->isValidDatabaseIdentifier($table) && $this->isValidDatabaseIdentifier($column);
        }

        return $this->isValidDatabaseIdentifier($mainIdentifier);
    }

    /**
     * Valida un identificador de base de datos individual.
     *
     * @param string $identifier
     * @return bool
     */
    private function isValidDatabaseIdentifier(string $identifier): bool
    {
        // Expresión regular para validar identificadores:
        // - Debe empezar con una letra o guion bajo.
        // - Seguido de letras, números o guiones bajos.
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $identifier)) {
            return false;
        }

        // Comprobar la existencia de patrones maliciosos
        if (str_contains($identifier, '--') || str_contains($identifier, '/*') || str_contains($identifier, ';')) {
            return false;
        }

        return true;
    }

    /**
     * Verifica si un identificador es una función SQL válida.
     *
     * @param string $identifier
     * @return bool
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
            if (!in_array($functionName, $allowedFunctions)) {
                return false;
            }

            // Validar argumentos básicos (permitir *, columnas simples, números y strings)
            if ($functionArgs === '*') {
                return true; // COUNT(*), etc.
            }

            // Permitir argumentos simples como column names, números, strings
            if (preg_match('/^[a-zA-Z0-9_.,\s\'"]+$/', $functionArgs)) {
                // Verificar que no contenga patrones maliciosos
                if (
                    !str_contains($functionArgs, '--') &&
                    !str_contains($functionArgs, '/*') &&
                    !str_contains($functionArgs, ';')
                ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Añade una cláusula WHERE.
     *
     * @param string $column
     * @param string $operator
     * @param mixed $value
     * @return self
     */
    public function where(string $column, string $operator, $value): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value,
            'type' => 'and',
        ];
        return $this;
    }

    /**
     * Añade una cláusula OR WHERE.
     *
     * @param string $column
     * @param string $operator
     * @param mixed $value
     * @return self
     */
    public function orWhere(string $column, string $operator, $value): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value,
            'type' => 'or',
        ];
        return $this;
    }

    /**
     * Añade una cláusula WHERE IN.
     *
     * @param string $column
     * @param array<int, mixed> $values
     * @return self
     */
    public function whereIn(string $column, array $values): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => 'IN',
            'value' => $values,
            'type' => 'and',
        ];
        return $this;
    }

    /**
     * Añade una cláusula WHERE NOT IN.
     *
     * @param string $column
     * @param array<int, mixed> $values
     * @return self
     */
    public function whereNotIn(string $column, array $values): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => 'NOT IN',
            'value' => $values,
            'type' => 'and',
        ];
        return $this;
    }

    /**
     * Añade una cláusula WHERE IS NULL.
     *
     * @param string $column
     * @return self
     */
    public function whereNull(string $column): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => 'IS NULL',
            'value' => null,
            'type' => 'and',
        ];
        return $this;
    }

    /**
     * Añade una cláusula WHERE IS NOT NULL.
     *
     * @param string $column
     * @return self
     */
    public function whereNotNull(string $column): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => 'IS NOT NULL',
            'value' => null,
            'type' => 'and',
        ];
        return $this;
    }

    /**
     * Añade una cláusula WHERE BETWEEN.
     *
     * @param string $column
     * @param mixed $min
     * @param mixed $max
     * @return self
     */
    public function whereBetween(string $column, $min, $max): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => 'BETWEEN',
            'value' => [$min, $max],
            'type' => 'and',
        ];
        return $this;
    }

    /**
     * Añade una cláusula WHERE con SQL raw.
     *
     * @param string $sql
     * @param array<int, mixed> $bindings
     * @return self
     */
    public function whereRaw(string $sql, array $bindings = []): self
    {
        $this->wheres[] = [
            'column' => '',
            'operator' => 'RAW',
            'value' => ['sql' => $sql, 'bindings' => $bindings],
            'type' => 'and',
        ];
        return $this;
    }

    /**
     * Añade una cláusula HAVING.
     *
     * @param string $column
     * @param string $operator
     * @param mixed $value
     * @return self
     */
    public function having(string $column, string $operator, $value): self
    {
        $this->having[] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value,
        ];
        return $this;
    }

    /**
     * Añade un INNER JOIN.
     *
     * @param string $table
     * @param string $firstCol
     * @param string $operator
     * @param string $secondCol
     * @return self
     */
    public function join(string $table, string $firstCol, string $operator, string $secondCol): self
    {
        $this->joins[] = [
            'type' => 'inner',
            'table' => $table,
            'first_col' => $firstCol,
            'operator' => $operator,
            'second_col' => $secondCol,
        ];
        return $this;
    }

    /**
     * Añade un LEFT JOIN.
     *
     * @param string $table
     * @param string $firstCol
     * @param string $operator
     * @param string $secondCol
     * @return self
     */
    public function leftJoin(string $table, string $firstCol, string $operator, string $secondCol): self
    {
        $this->joins[] = [
            'type' => 'left',
            'table' => $table,
            'first_col' => $firstCol,
            'operator' => $operator,
            'second_col' => $secondCol,
        ];
        return $this;
    }

    /**
     * Añade un RIGHT JOIN.
     *
     * @param string $table
     * @param string $firstCol
     * @param string $operator
     * @param string $secondCol
     * @return self
     */
    public function rightJoin(string $table, string $firstCol, string $operator, string $secondCol): self
    {
        $this->joins[] = [
            'type' => 'right',
            'table' => $table,
            'first_col' => $firstCol,
            'operator' => $operator,
            'second_col' => $secondCol,
        ];
        return $this;
    }

    /**
     * Agrupa los resultados.
     *
     * @param array<int, string>|string $columns
     * @return self
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
     * Ordena los resultados.
     *
     * @param string $column
     * @param string $direction
     * @return self
     */
    public function orderBy(string $column, string $direction = 'asc'): self
    {
        // Validate column name for security
        if (!$this->isSafeIdentifier($column)) {
            throw new VersaORMException(sprintf('Invalid or malicious column name in ORDER BY: %s', $column));
        }

        // Validate direction to prevent injection
        $direction = strtoupper($direction);
        if (!in_array($direction, ['ASC', 'DESC'])) {
            throw new VersaORMException(sprintf('Invalid ORDER BY direction. Only ASC and DESC are allowed: %s', $direction));
        }

        $this->orderBy = ['column' => $column, 'direction' => $direction];
        return $this;
    }

    /**
     * Limita el número de resultados.
     *
     * @param int $count
     * @return self
     */
    public function limit(int|string $count): self
    {
        $this->limit = (int) $count;
        return $this;
    }

    /**
     * Especifica el punto de inicio para la paginación.
     *
     * @param int $count
     * @return self
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
     * @return self
     */
    public function with($relations): self
    {
        if (is_string($relations)) {
            $relations = [$relations];
        }

        if (!$this->modelClass || !class_exists($this->modelClass)) {
            throw new \Exception('Cannot eager load relations without a valid model class.');
        }

        $resolvedRelations = [];
        foreach ($relations as $relationName) {
            if (!method_exists($this->modelClass, $relationName)) {
                throw new \Exception(sprintf("Relation method '%s' not found in model '%s'.", $relationName, $this->modelClass));
            }

            // Crear una instancia temporal del modelo para llamar al método de relación
            // Para evitar problemas con el ORM en la instancia temporal, pasamos null
            $tempModel = new $this->modelClass($this->table, null);

            $relationInstance = $tempModel->{$relationName}();

            if (!$relationInstance instanceof \VersaORM\Relations\Relation) {
                throw new \Exception(sprintf("Method '%s' in model '%s' does not return a valid Relation instance.", $relationName, $this->modelClass));
            }

            $relationType = (new \ReflectionClass($relationInstance))->getShortName();
            $relationData = [
                'name' => $relationName,
                'type' => $relationType,
                'related_table' => $relationInstance->query->getTable(),
            ];

            // Extraer claves específicas según el tipo de relación
            switch ($relationType) {
                case 'HasOne':
                case 'HasMany':
                    /** @var \VersaORM\Relations\HasOne|\VersaORM\Relations\HasMany $relationInstance */
                    $relationData['foreign_key'] = $relationInstance->foreignKey;
                    $relationData['local_key'] = $relationInstance->localKey;
                    break;
                case 'BelongsTo':
                    /** @var \VersaORM\Relations\BelongsTo $relationInstance */
                    $relationData['foreign_key'] = $relationInstance->foreignKey;
                    $relationData['owner_key'] = $relationInstance->ownerKey; // Usar owner_key para BelongsTo
                    break;
                case 'BelongsToMany':
                    /** @var \VersaORM\Relations\BelongsToMany $relationInstance */
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
        $results = $this->execute('get');
        $models = [];
        if (!is_array($results)) {
            return $models;
        }
        $modelClass = $this->modelClass ?: VersaModel::class;
        foreach ($results as $result) {
            if (is_array($result)) {
                /** @var VersaModel $model */
                $model = new $modelClass($this->table, $this->orm);
                assert($model instanceof VersaModel);
                $model->loadInstance($result);
                $models[] = $model;
            }
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
        $result = $this->execute('get');
        if (!is_array($result)) {
            return [];
        }
        // Forzar tipo correcto para PHPStan
        return array_values(array_filter($result, 'is_array'));
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
        $result = $this->execute('first');
        return is_array($result) ? $result : null;
    }

    /**
     * Ejecuta la consulta y devuelve el primer objeto resultado como VersaModel, o null.
     *
     * @return VersaModel|null
     */
    public function findOne(): ?VersaModel
    {
        $result = $this->execute('first');
        if (is_array($result) && !empty($result)) {
            $modelClass = $this->modelClass ?: VersaModel::class;
            /** @var VersaModel $model */
            $model = new $modelClass($this->table, $this->orm);
            assert($model instanceof VersaModel);
            $model->loadInstance($result);
            return $model;
        }
        return null;
    }

    /**
     * Busca un registro por su clave primaria.
     *
     * @param mixed $id
     * @param string $pk
     * @return mixed
     */
    public function find($id, string $pk = 'id')
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
     * @return VersaModel|null The first result as a VersaModel instance, or null if no result is found.
     */
    public function first(): ?VersaModel
    {
        $result = $this->execute('first');
        if (is_array($result) && !empty($result)) {
            $modelClass = $this->modelClass ?: VersaModel::class;
            /** @var VersaModel $model */
            $model = new $modelClass($this->table, $this->orm);
            assert($model instanceof VersaModel);
            $model->loadInstance($result);
            return $model;
        }
        return null;
    }

    /**
     * Ejecuta una consulta de conteo.
     *
     * @return int
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
     *
     * @return bool
     */
    public function exists(): bool
    {
        return (bool) $this->execute('exists');
    }

    /**
     * Inserta un nuevo registro.
     *
     * @param array<string, mixed> $data
     * @return bool
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
     * @return int|string|null
     */
    public function insertGetId(array $data)
    {
        $result = $this->execute('insertGetId', $data);
        if (is_int($result) || is_string($result)) {
            return $result;
        }
        return null;
    }

    /**
     * Actualiza los registros que coincidan con las cláusulas WHERE.
     *
     * @param array<string, mixed> $data
     * @return self
     */
    public function update(array $data): self
    {
        $this->execute('update', $data);
        return $this;
    }

    /**
     * Elimina los registros que coincidan con las cláusulas WHERE.
     *
     * @return null
     */
    public function delete(): ?VersaModel
    {
        $this->execute('delete');
        return null;
    }

    /**
     * Crear un nuevo objeto (dispense).
     *
     * @return VersaModel
     */
    public function dispense(): VersaModel
    {
        error_log('[DEBUG] Executing SQL with QueryBuilder');
        return new VersaModel($this->table, $this->orm);
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
        return $this->wheres;
    }

    /**
     * Ejecuta la consulta usando la instancia de VersaORM.
     *
     * @param string $method
     * @param array<string, mixed>|null $data
     * @return mixed
     */
    private function execute(string $method, ?array $data = null)
    {
        error_log('[DEBUG] Executing query from QueryBuilder...');
        if (!($this->orm instanceof VersaORM)) {
            throw new \Exception('VersaORM instance is required for QueryBuilder execution.');
        }

        $params = $this->buildPayload($method, $data);

        // Llamar al método execute de VersaORM usando reflexión
        $reflection = new \ReflectionClass($this->orm);
        $executeMethod = $reflection->getMethod('execute');
        $executeMethod->setAccessible(true);

        // Determinar la acción principal. Para operaciones de escritura, es el método mismo.
        // Para lectura, es 'query'.
        $batchMethods = ['insertMany', 'updateMany', 'deleteMany', 'upsertMany'];
        $writeMethods = ['insert', 'insertGetId', 'update', 'delete'];

        if (in_array($method, $batchMethods)) {
            // Las operaciones de lote van como 'query' con el método específico en params
            $action = 'query';
            $params['method'] = $method;
        } elseif (in_array($method, $writeMethods)) {
            // Las operaciones de escritura normales van como su propio método
            $action = $method;
        } else {
            // Las operaciones de lectura van como 'query'
            $action = 'query';
            $params['method'] = $method;
        }

        return $executeMethod->invoke($this->orm, $action, $params);
    }

    /**
     * @param string $method
     * @param array<string, mixed>|null $data
     * @return array<string, mixed>
     */
    private function buildPayload(string $method, ?array $data = null): array
    {
        $params = [
            'table' => $this->table,
            'select' => $this->selects,
            'joins' => $this->joins,
            'where' => $this->processWheres(),
            'orderBy' => $this->orderBy ? [$this->orderBy] : [],
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
            if (in_array($method, $batchMethods)) {
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
     * Obtiene el nombre de la tabla asociada a este QueryBuilder.
     *
     * @return string
     */
    public function getTable(): string
    {
        return $this->table;
    }

    /**
     * Obtiene una instancia del modelo asociado a este QueryBuilder.
     *
     * @return VersaModel
     */
    public function getModelInstance(): VersaModel
    {
        $modelClass = $this->modelClass ?: VersaModel::class;
        /** @var VersaModel $model */
        $model = new $modelClass($this->table, $this->orm);
        assert($model instanceof VersaModel);
        return $model;
    }

    //======================================================================
    // BATCH OPERATIONS (LOTE) - Tarea 2.2
    //======================================================================

    /**
     * Inserta múltiples registros en una sola operación batch optimizada.
     * Utiliza INSERT INTO table (cols) VALUES (val1), (val2), ... para máximo rendimiento.
     *
     * @param array<int, array<string, mixed>> $records Array de arrays asociativos con los datos a insertar
     * @param int $batchSize Tamaño del lote para operaciones muy grandes (default: 1000)
     * @return array<string, mixed> Información sobre la operación: total_inserted, batches_processed, etc.
     * @throws VersaORMException Si los datos son inválidos o la operación falla
     */
    public function insertMany(array $records, int $batchSize = 1000): array
    {
        if (empty($records)) {
            throw new VersaORMException('insertMany requires at least one record to insert');
        }

        // Validar que todos los registros tengan la misma estructura
        $firstKeys = array_keys($records[0]);
        foreach ($records as $index => $record) {
            if (!is_array($record) || empty($record)) {
                throw new VersaORMException(sprintf('Record at index %d is invalid or empty', $index));
            }

            $currentKeys = array_keys($record);
            if ($currentKeys !== $firstKeys) {
                throw new VersaORMException(sprintf(
                    'Record at index %d has different columns. Expected: [%s], Got: [%s]',
                    $index,
                    implode(', ', $firstKeys),
                    implode(', ', $currentKeys)
                ));
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

        return $this->execute('insertMany', $params);
    }

    /**
     * Actualiza múltiples registros que coincidan con las condiciones WHERE.
     * Utiliza transacciones y consultas optimizadas según la base de datos.
     *
     * @param array<string, mixed> $data Datos a actualizar
     * @param int $maxRecords Límite máximo de registros a actualizar por seguridad (default: 10000)
     * @return array<string, mixed> Información sobre la operación: rows_affected, etc.
     * @throws VersaORMException Si no hay condiciones WHERE o la operación falla
     */
    public function updateMany(array $data, int $maxRecords = 10000): array
    {
        if (empty($data)) {
            throw new VersaORMException('updateMany requires data to update');
        }

        if (empty($this->wheres)) {
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

        return $this->execute('updateMany', $params);
    }

    /**
     * Elimina múltiples registros que coincidan con las condiciones WHERE.
     * Utiliza DELETE optimizado con límites de seguridad.
     *
     * @param int $maxRecords Límite máximo de registros a eliminar por seguridad (default: 10000)
     * @return array<string, mixed> Información sobre la operación: rows_affected, etc.
     * @throws VersaORMException Si no hay condiciones WHERE o la operación falla
     */
    public function deleteMany(int $maxRecords = 10000): array
    {
        if (empty($this->wheres)) {
            throw new VersaORMException('deleteMany requires WHERE conditions to prevent accidental mass deletions');
        }

        // Validar límite máximo por seguridad
        if ($maxRecords <= 0 || $maxRecords > 100000) {
            throw new VersaORMException('Max records limit must be between 1 and 100000');
        }

        $params = [
            'max_records' => $maxRecords,
        ];

        return $this->execute('deleteMany', $params);
    }

    /**
     * Upsert (INSERT ... ON DUPLICATE KEY UPDATE) para múltiples registros.
     * Inserta registros nuevos o actualiza los existentes basado en claves únicas.
     *
     * @param array<int, array<string, mixed>> $records Array de registros
     * @param array<int, string> $uniqueKeys Columnas que determinan duplicados
     * @param array<int, string> $updateColumns Columnas a actualizar en caso de duplicado (opcional)
     * @param int $batchSize Tamaño del lote (default: 1000)
     * @return array<string, mixed> Información sobre la operación
     * @throws VersaORMException Si los datos son inválidos
     */
    public function upsertMany(
        array $records,
        array $uniqueKeys,
        array $updateColumns = [],
        int $batchSize = 1000
    ): array {
        if (empty($records)) {
            throw new VersaORMException('upsertMany requires at least one record');
        }

        if (empty($uniqueKeys)) {
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
                        sprintf('Record at index %d is missing unique key: %s', $index, $key)
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

        return $this->execute('upsertMany', $params);
    }
}
