<?php

declare(strict_types=1);

namespace VersaORM;

/**
 * QueryBuilder - Constructor de consultas para VersaORM
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
    private $orm; // Puede ser array (config) o instancia de VersaORM
    private string $table;
    private array $selects = [];
    private array $wheres = [];
    private array $joins = [];
    private ?array $orderBy = null;
    private ?int $limit = null;
    private ?int $offset = null;
    private ?array $groupBy = null;
    private array $having = [];

    public function __construct($orm, string $table)
    {
        $this->orm = $orm;
        $this->table = $table;
    }

    /**
     * Especifica las columnas a seleccionar.
     *
     * @param array|null $columns
     * @return self
     */
    public function select(?array $columns = ['*']): self
    {
        $this->selects = $columns ?? ['*'];
        return $this;
    }

    /**
     * Añade una cláusula WHERE.
     *
     * @param string|null $column
     * @param string|null $operator
     * @param mixed $value
     * @return self
     */
    public function where(?string $column, ?string $operator, $value): self
    {
        if ($column === null) {
            $column = '';
        }
        if ($operator === null) {
            $operator = '=';
        }
        $this->wheres[] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value,
            'type' => 'and'
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
            'type' => 'or'
        ];
        return $this;
    }

    /**
     * Añade una cláusula WHERE IN.
     *
     * @param string $column
     * @param array $values
     * @return self
     */
    public function whereIn(string $column, array $values): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => 'IN',
            'value' => $values,
            'type' => 'and'
        ];
        return $this;
    }

    /**
     * Añade una cláusula WHERE NOT IN.
     *
     * @param string $column
     * @param array $values
     * @return self
     */
    public function whereNotIn(string $column, array $values): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => 'NOT IN',
            'value' => $values,
            'type' => 'and'
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
            'type' => 'and'
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
            'type' => 'and'
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
            'type' => 'and'
        ];
        return $this;
    }

    /**
     * Añade una cláusula WHERE con SQL raw.
     *
     * @param string $sql
     * @param array $bindings
     * @return self
     */
    public function whereRaw(string $sql, array $bindings = []): self
    {
        $this->wheres[] = [
            'column' => '',
            'operator' => 'RAW',
            'value' => ['sql' => $sql, 'bindings' => $bindings],
            'type' => 'and'
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
            'value' => $value
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
            'on' => "$firstCol $operator $secondCol"
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
            'on' => "$firstCol $operator $secondCol"
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
            'on' => "$firstCol $operator $secondCol"
        ];
        return $this;
    }

    /**
     * Agrupa los resultados.
     *
     * @param array|string $columns
     * @return self
     */
    public function groupBy($columns): self
    {
        // Implementar lógica de GROUP BY
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
        $this->limit = (int)$count;
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

    // ========== MÉTODOS QUE DEVUELVEN OBJETOS MANIPULABLES ==========
    
    /**
     * Ejecuta la consulta SELECT y devuelve un array de objetos VersaModel manipulables
     *
     * @return VersaModel[]
     */
    public function findAll(): array
    {
        $results = $this->execute('get');
        $models = [];
        
        foreach ($results as $result) {
            $model = new VersaModel($this->table, $this->orm);
            $model->loadInstance($result);
            $models[] = $model;
        }
        
        return $models;
    }

    // ========== MÉTODOS QUE DEVUELVEN ARRAYS (para JSON/API) ==========
    
    /**
     * Ejecuta la consulta SELECT y devuelve array de arrays de datos (para JSON/API)
     *
     * @return array
     */
    public function get(): array
    {
        return $this->execute('get');
    }
    
    /**
     * Alias de get() - devuelve array de arrays de datos
     *
     * @return array
     */
    public function getAll(): array
    {
        return $this->get();
    }
    
    /**
     * Obtiene el primer registro como array (para JSON/API)
     *
     * @return array|null
     */
    public function firstArray(): ?array
    {
        return $this->execute('first');
    }

    /**
     * Ejecuta la consulta y devuelve el primer objeto resultado como VersaModel, o null.
     *
     * @return VersaModel|null
     */
    public function findOne(): ?VersaModel
    {
        $result = $this->execute('first');
        if ($result) {
            $model = new VersaModel($this->table, $this->orm);
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
        if ($result) {
            $model = new VersaModel($this->table, $this->orm);
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
        return (int) $this->execute('count');
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
     * @param array $data
     * @return self
     */
    public function insert(array $data): self
    {
        $this->execute('insert', $data);
        return $this;
    }

    /**
     * Inserta un registro y devuelve su ID autoincremental.
     *
     * @param array $data
     * @return mixed
     */
    public function insertGetId(array $data)
    {
        return $this->execute('insertGetId', $data);
    }

    /**
     * Actualiza los registros que coincidan con las cláusulas WHERE.
     *
     * @param array $data
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
     * @return self
     */
    public function delete(): self
    {
        $this->execute('delete');
        return $this;
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
     * @return array
     */
    private function processWheres(): array
    {
        $processedWheres = [];

        foreach ($this->wheres as $where) {
            if ($where['operator'] === 'RAW') {
                // Para whereRaw, extraer el SQL y los bindings de forma que el backend lo entienda
                $processedWheres[] = [
                    'type' => 'raw',
                    'sql' => $where['value']['sql'],
                    'bindings' => $where['value']['bindings'],
                    'conjunction' => $where['type'] // 'and' o 'or'
                ];
            } else {
                $processedWheres[] = $where;
            }
        }

        return $processedWheres;
    }

    /**
     * Ejecuta la consulta usando la instancia de VersaORM.
     *
     * @param string $method
     * @param array|null $data
     * @return mixed
     */
    private function execute(string $method, ?array $data = null)
    {
        if (!($this->orm instanceof VersaORM)) {
            throw new \Exception('VersaORM instance is required for QueryBuilder execution.');
        }

$params = [
            'table' => $this->table,
            'select' => $this->selects,
            'joins' => $this->joins,
            'where' => $this->processWheres(),
            'orderBy' => $this->orderBy ? [$this->orderBy] : [],
            'limit' => $this->limit,
            'offset' => $this->offset,
            'method' => $method
        ];

        if ($data !== null) {
            $params['data'] = $data;
        }

        // Llamar al método execute de VersaORM usando reflexión
        $reflection = new \ReflectionClass($this->orm);
        $executeMethod = $reflection->getMethod('execute');
        $executeMethod->setAccessible(true);

        return $executeMethod->invoke($this->orm, 'query', $params);
    }

}
