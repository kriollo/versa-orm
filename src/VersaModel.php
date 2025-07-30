<?php

declare(strict_types=1);

namespace VersaORM;

/**
 * VersaModel - Modelo base ActiveRecord para VersaORM
 *
 * PROPÓSITO: Representa un registro individual de la base de datos como objeto
 * RETORNA: Siempre objetos manipulables (store, trash, propiedades dinámicas)
 * USO: Para operaciones CRUD individuales y manipulación de registros
 *
 * @package VersaORM
 * @version 1.0.0
 * @author VersaORM Team
 * @license MIT
 */
class VersaModel
{
    private string $table;
    private $orm; // Puede ser array (config) o instancia de VersaORM
    private array $attributes = [];
    private static $ormInstance;

    public function __construct(string $table, $orm)
    {
        $this->table = $table;
        $this->orm = $orm;
    }

    /**
     * Configura la instancia global del ORM para métodos estáticos.
     *
     * @param VersaORM $orm
     * @return void
     */
    public static function setORM(VersaORM $orm): void
    {
        self::$ormInstance = $orm;
    }

    /**
     * Cargar los datos del modelo desde la base de datos (método de instancia).
     *
     * @param mixed $data - Puede ser un ID para buscar o un array de datos para cargar directamente
     * @param string $pk
     * @return self
     */
    public function loadInstance($data, string $pk = 'id'): self
    {
        // Si $data es un array, cargar directamente los datos
        if (is_array($data)) {
            $this->attributes = $data;
            return $this;
        }

        // Si es un ID, buscar en la base de datos
        $orm = $this->orm ?? self::$ormInstance;
        if (!($orm instanceof VersaORM)) {
            throw new \Exception("No ORM instance available for load operation");
        }

        $result = $orm->exec("SELECT * FROM {$this->table} WHERE {$pk} = ?", [$data]);
        if (!empty($result)) {
            $this->attributes = $result[0];
        } else {
            throw new \Exception("Record not found");
        }

        return $this;
    }

    /**
     * Guardar el modelo en la base de datos.
     *
     * @return void
     */
    public function store(): void
    {
        $orm = $this->orm ?? self::$ormInstance;
        if (!($orm instanceof VersaORM)) {
            throw new \Exception("No ORM instance available for store operation");
        }

        if (isset($this->attributes['id'])) {
            // UPDATE existente
            $fields = [];
            $params = [];
            foreach ($this->attributes as $key => $value) {
                if ($key !== 'id') {
                    $fields[] = "{$key} = ?";
                    $params[] = $value;
                }
            }
            $params[] = $this->attributes['id'];

            $sql = "UPDATE {$this->table} SET " . implode(', ', $fields) . " WHERE id = ?";
            $orm->exec($sql, $params);
        } else {
            // INSERT nuevo - filtrar campos que no deben insertarse manualmente
            $filteredAttributes = $this->attributes;
            unset($filteredAttributes['id']); // No insertar ID manualmente
            unset($filteredAttributes['created_at']); // Dejar que MySQL lo maneje
            unset($filteredAttributes['updated_at']); // Dejar que MySQL lo maneje

            if (empty($filteredAttributes)) {
                throw new \Exception('No data to insert');
            }

            $fields = array_keys($filteredAttributes);
            $placeholders = array_fill(0, count($fields), '?');

            $sql = "INSERT INTO {$this->table} (" . implode(', ', $fields) . ") VALUES (" . implode(', ', $placeholders) . ")";
            $orm->exec($sql, array_values($filteredAttributes));

            // Obtener el ID del registro recién insertado
            // Como LAST_INSERT_ID() no funciona como esperado, buscaremos el registro más reciente
            // que coincida con los datos que acabamos de insertar
            $whereConditions = [];
            $whereParams = [];
            
            // Usar campos únicos para encontrar el registro
            if (isset($filteredAttributes['email'])) {
                $whereConditions[] = "email = ?";
                $whereParams[] = $filteredAttributes['email'];
            } else {
                // Si no hay email, usar otros campos como fallback
                foreach ($filteredAttributes as $key => $value) {
                    if (is_string($value) || is_numeric($value)) {
                        $whereConditions[] = "{$key} = ?";
                        $whereParams[] = $value;
                        break; // Solo usar el primer campo válido
                    }
                }
            }
            
            if (!empty($whereConditions)) {
                $whereClause = implode(' AND ', $whereConditions);
                $result = $orm->exec("SELECT * FROM {$this->table} WHERE {$whereClause} ORDER BY id DESC LIMIT 1", $whereParams);
                
                if (!empty($result) && isset($result[0])) {
                    $this->attributes = array_merge($this->attributes, $result[0]);
                }
            }
        }
    }

    /**
     * Eliminar el registro del modelo en la base de datos.
     *
     * @return void
     */
    public function trash(): void
    {
        if (!isset($this->attributes['id'])) {
            throw new \Exception("Cannot delete without an ID");
        }

        $orm = $this->orm ?? self::$ormInstance;
        if (!($orm instanceof VersaORM)) {
            throw new \Exception("No ORM instance available for trash operation");
        }

        $sql = "DELETE FROM {$this->table} WHERE id = ?";
        $orm->exec($sql, [$this->attributes['id']]);

        // Limpiar los atributos ya que el registro fue eliminado
        $this->attributes = [];
    }

    /**
     * Asignar valor a un atributo.
     *
     * @param string $key
     * @param mixed $value
     */
    public function __set(string $key, $value)
    {
        $this->attributes[$key] = $value;
    }

    /**
     * Obtener el valor de un atributo.
     *
     * @param string $key
     * @return mixed
     */
    public function __get(string $key)
    {
        return $this->attributes[$key] ?? null;
    }

    /**
     * Exportar el modelo a un array.
     *
     * @return array
     */
    public function export(): array
    {
        return $this->attributes;
    }

    /**
     * Exportar una colección de modelos a un array de arrays.
     *
     * @param array $models Array de instancias de Model
     * @return array
     */
    public static function exportAll(array $models): array
    {
        return array_map(function ($model) {
            if ($model instanceof self) {
                return $model->export();
            }
            // Si no es un modelo, devolver tal como está
            return $model;
        }, $models);
    }

    /**
     * Verificar si existe un atributo.
     *
     * @param string $key
     * @return bool
     */
    public function __isset(string $key): bool
    {
        return isset($this->attributes[$key]);
    }

    /**
     * Eliminar un atributo.
     *
     * @param string $key
     * @return void
     */
    public function __unset(string $key): void
    {
        unset($this->attributes[$key]);
    }

    /**
     * Obtiene el nombre de la tabla.
     *
     * @return string
     */
    public function getTable(): string
    {
        return $this->table;
    }

    /**
     * Obtiene todos los datos del modelo.
     *
     * @return array
     */
    public function getData(): array
    {
        return $this->attributes;
    }

    /**
     * Crea un nuevo modelo vacío (método estático).
     *
     * @param string $table
     * @return self
     */
    public static function dispense(string $table): self
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call Model::setORM() first.");
        }
        return new self($table, self::$ormInstance);
    }

    /**
     * Cargar un modelo por ID (método estático).
     *
     * @param string $table
     * @param mixed $id
     * @param string $pk
     * @return self|null
     */
    public static function load(string $table, $id, string $pk = 'id'): ?self
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call Model::setORM() first.");
        }

        try {
            $data = self::$ormInstance->exec("SELECT * FROM {$table} WHERE {$pk} = ?", [$id]);
            if (empty($data)) {
                return null;
            }

            $model = new self($table, self::$ormInstance);
            $model->attributes = $data[0];
            return $model;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Crea un nuevo modelo vacío (método de instancia).
     *
     * @param string $table
     * @return self
     */
    public function dispenseInstance(string $table): self
    {
        return new self($table, $this->orm);
    }

    // ========== MÉTODOS GENERALES DE CONSULTA ==========

    /**
     * Cuenta registros en una tabla con condiciones opcionales.
     *
     * @param string $table
     * @param string|null $conditions
     * @param array $bindings
     * @return int
     */
    public static function count(string $table, ?string $conditions = null, array $bindings = []): int
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }
        $sql = "SELECT COUNT(*) as count FROM {$table}";
        if ($conditions) {
            $sql .= " WHERE {$conditions}";
        }
        $result = self::$ormInstance->exec($sql, $bindings);
        return (int) ($result[0]['count'] ?? 0);
    }

    /**
     * Obtiene todos los registros de una tabla como array de arrays.
     *
     * @param string $sql
     * @param array $bindings
     * @return array
     */
    public static function getAll(string $sql, array $bindings = []): array
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }
        return self::$ormInstance->exec($sql, $bindings);
    }

    /**
     * Obtiene una sola fila como array.
     *
     * @param string $sql
     * @param array $bindings
     * @return array|null
     */
    public static function getRow(string $sql, array $bindings = []): ?array
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }
        $result = self::$ormInstance->exec($sql, $bindings);
        return $result[0] ?? null;
    }

    /**
     * Obtiene un solo valor de una consulta.
     *
     * @param string $sql
     * @param array $bindings
     * @return mixed
     */
    public static function getCell(string $sql, array $bindings = [])
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }
        $result = self::$ormInstance->exec($sql, $bindings);
        if (!empty($result) && is_array($result[0])) {
            return array_values($result[0])[0] ?? null;
        }
        return null;
    }


    // ========== MÉTODOS ACTIVERECORD ESTÁTICOS ==========

    /**
     * Busca un registro por ID y lo devuelve como modelo.
     *
     * @param string $table
     * @param mixed $id
     * @param string $pk
     * @return self|null
     */
    public static function findOne(string $table, $id, string $pk = 'id'): ?self
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }
        return self::$ormInstance->table($table)->where($pk, '=', $id)->findOne();
    }

    /**
     * Busca registros con condiciones y los devuelve como array de modelos.
     *
     * @param string $table
     * @param string|null $conditions
     * @param array $bindings
     * @return self[]
     */
    public static function findAll(string $table, ?string $conditions = null, array $bindings = []): array
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }

        $queryBuilder = self::$ormInstance->table($table);
        if ($conditions) {
            // Agregar condiciones raw si es necesario
            $queryBuilder->whereRaw($conditions, $bindings);
        }
        return $queryBuilder->findAll();
    }

    /**
     * Guarda un modelo (método estático de conveniencia).
     *
     * @param self $model
     * @return void
     */
    public static function storeModel(self $model): void
    {
        $model->store();
    }

    /**
     * Elimina un modelo (método estático de conveniencia).
     *
     * @param self $model
     * @return void
     */
    public static function trashModel(self $model): void
    {
        $model->trash();
    }
}
