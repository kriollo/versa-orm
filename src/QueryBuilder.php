<?php

declare(strict_types=1);

namespace VersaORM;

/**
 * VersaORMQueryBuilder - Clase de construcción de consultas para VersaORM
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
    public function limit(int $count): self
    {
        $this->limit = $count;
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
     * Ejecuta la consulta SELECT y devuelve un array de modelos.
     *
     * @return Model[]
     */
    public function findAll(): array
    {
        $results = $this->execute('get');
        $models = [];
        foreach ($results as $result) {
            $model = new Model($this->table, $this->orm);
            $model->loadInstance($result);
            $models[] = $model;
        }
        return $models;
    }

    /**
     * Ejecuta la consulta SELECT y devuelve un array de arrays de datos
     *
     * @return array
     */
    public function getAll(): array
    {
        return $this->execute('get');
    }

    /**
     * Ejecuta la consulta y devuelve el primer objeto resultado como modelo, o null.
     *
     * @return Model|null
     */
    public function findOne(): ?Model
    {
        $result = $this->execute('first');
        if ($result) {
            $model = new Model($this->table, $this->orm);
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
     * Retrieves the first result from the executed query and returns it as a Model instance.
     *
     * Executes the query using the 'first' mode, which is expected to return a single result.
     * If a result is found, a new Model instance is created, loaded with the result data, and returned.
     * If no result is found, returns null.
     *
     * @return Model|null The first result as a Model instance, or null if no result is found.
     */
    public function first(): ?Model
    {
        $result = $this->execute('first');
        if ($result) {
            $model = new Model($this->table, $this->orm);
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
     * @return Model
     */
    public function dispense(): Model
    {
        error_log('[DEBUG] Executing SQL with QueryBuilder');
        return new Model($this->table, $this->orm);
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
            'where' => $this->wheres,
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
