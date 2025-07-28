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
    private array $config;
    private string $table;
    private array $selects = [];
    private array $wheres = [];
    private array $joins = [];
    private ?array $orderBy = null;
    private ?int $limit = null;
    private ?int $offset = null;

    public function __construct(array $config, string $table)
    {
        $this->config = $config;
        $this->table = $table;
    }

    /**
     * Especifica las columnas a seleccionar.
     *
     * @param array $columns
     * @return self
     */
    public function select(array $columns): self
    {
        $this->selects = $columns;
        return $this;
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
     * Ejecuta la consulta SELECT y devuelve un array de objetos.
     *
     * @return array
     */
    public function get(): array
    {
        return $this->execute('get');
    }

    /**
     * Ejecuta la consulta y devuelve el primer objeto resultado, o null.
     *
     * @return mixed
     */
    public function first()
    {
        return $this->execute('first');
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
     * @return mixed
     */
    public function insert(array $data)
    {
        return $this->execute('insert', $data);
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
     * @return mixed
     */
    public function update(array $data)
    {
        return $this->execute('update', $data);
    }

    /**
     * Elimina los registros que coincidan con las cláusulas WHERE.
     *
     * @return mixed
     */
    public function delete()
    {
        return $this->execute('delete');
    }

    /**
     * Crear un nuevo objeto (dispense).
     *
     * @return Model
     */
    public function dispense(): Model
    {
        return new Model($this->table, $this->config);
    }

    /**
     * Ejecuta la consulta en el binario Rust.
     *
     * @param string $method
     * @param array|null $data
     * @return mixed
     */
    private function execute(string $method, ?array $data = null)
    {
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

        return $this->executeRustCommand('query', $params);
    }

    /**
     * Ejecuta un comando en el binario de Rust.
     *
     * @param string $action
     * @param array $params
     * @return mixed
     */
    private function executeRustCommand(string $action, array $params)
    {
        $payload = json_encode([
            'config' => $this->config,
            'action' => $action,
            'params' => $params
        ]);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception('Failed to encode JSON payload: ' . json_last_error_msg());
        }

        // Detectar el sistema operativo para usar el binario correcto
        $binaryPath = __DIR__ . '/../versaorm_cli/target/release/versaorm_cli';
        if (PHP_OS_FAMILY === 'Windows') {
            $binaryPath .= '.exe';
        }

        // Verificar que el binario existe
        if (!file_exists($binaryPath)) {
            throw new \Exception("VersaORM binary not found at: {$binaryPath}. Please compile it with: cd versaorm_cli && cargo build --release");
        }

        $command = sprintf('%s %s', $binaryPath, escapeshellarg($payload));
        $output = shell_exec($command);

        if ($output === null) {
            throw new \Exception('Failed to execute the VersaORM binary. Is the path correct and does it have execution permissions?');
        }

        $response = json_decode($output, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception('Failed to decode JSON response from binary: ' . json_last_error_msg());
        }

        if (isset($response['status']) && $response['status'] === 'error') {
            $errorCode = $response['error']['code'] ?? 'UNKNOWN_ERROR';
            $errorMessage = $response['error']['message'] ?? 'An unknown error occurred.';
            throw new \Exception(sprintf('VersaORM Error [%s]: %s', $errorCode, $errorMessage));
        }

        return $response['data'] ?? null;
    }
}
