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
use VersaORM\Traits\HasRelationships;

class VersaModel
{
    use HasRelationships;

    protected string $table;
    /** @var VersaORM|array<string, mixed>|null */
    private $orm; // Puede ser array (config) o instancia de VersaORM
    /** @var array<string, mixed> */
    private array $attributes = [];
    /** @var VersaORM|null */
    private static ?VersaORM $ormInstance = null;

    /**
     * @param string $table
     * @param VersaORM|array<string, mixed>|null $orm
     */
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
     * @param array<string, mixed>|int|string $data Puede ser un ID para buscar o un array de datos para cargar directamente
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
        if (is_array($result) && !empty($result) && is_array($result[0])) {
            $this->attributes = $result[0];
        } else {
            throw new \Exception("Record not found or invalid result format");
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

                if (is_array($result) && !empty($result) && is_array($result[0])) {
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
    public function __set(string $key, $value): void
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
        if (isset($this->attributes[$key])) {
            return $this->attributes[$key];
        }

        if ($this->relationLoaded($key)) {
            return $this->relations[$key];
        }

        if (method_exists($this, $key)) {
            return $this->getRelationshipFromMethod($key);
        }

        return null;
    }

    /**
     * Obtiene el valor de un atributo del modelo.
     *
     * @param string $key
     * @return mixed|null
     */
    public function getAttribute(string $key)
    {
        return $this->attributes[$key] ?? null;
    }

    /**
     * Exportar el modelo a un array.
     *
     * @return array<string, mixed>
     */
    public function export(): array
    {
        return $this->attributes;
    }

    /**
     * Exportar una colección de modelos a un array de arrays.
     *
     * @param array<self> $models Array de instancias de Model
     * @return array<int, array<string, mixed>>
     */
    public static function exportAll(array $models): array
    {
        $exported = [];
        foreach ($models as $model) {
            if ($model instanceof self) {
                $exported[] = $model->export();
            }
        }
        return $exported;
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

    public function getForeignKey(): string
    {
        return strtolower(basename(str_replace('\\', '/', get_class($this)))) . '_id';
    }

    public function getKeyName(): string
    {
        return 'id';
    }

    protected function getRelationName(): string
    {
        $class = new \ReflectionClass($this);
        return strtolower($class->getShortName());
    }

    public function newQuery(): QueryBuilder
    {
        $ormInstance = $this->orm ?? self::$ormInstance;
        $config = null;

        if ($ormInstance instanceof VersaORM) {
            $config = $ormInstance->getConfig();
        } elseif (is_array($ormInstance)) {
            $config = $ormInstance;
        }

        if ($config === null) {
            throw new \Exception('ORM configuration not found.');
        }

        return (new VersaORM($config))->table($this->table, static::class);
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
     * @return array<string, mixed>
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
     * @param int|string $id
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
            if (!is_array($data) || empty($data) || !is_array($data[0])) {
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
     * @param array<int, mixed> $bindings
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
        if (is_array($result) && isset($result[0]) && is_array($result[0]) && isset($result[0]['count'])) {
            return (int) $result[0]['count'];
        }
        return 0;
    }


    /**
     * Obtiene todos los registros de una tabla como array de arrays.
     *
     * @param string $sql
     * @param array<int, mixed> $bindings
     * @return array<int, array<string, mixed>>
     */
    public static function getAll(string $sql, array $bindings = []): array
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }
        $result = self::$ormInstance->exec($sql, $bindings);
        if (is_array($result)) {
            return array_filter($result, 'is_array');
        }
        return [];
    }

    /**
     * Obtiene una sola fila como array.
     *
     * @param string $sql
     * @param array<int, mixed> $bindings
     * @return array<string, mixed>|null
     */
    public static function getRow(string $sql, array $bindings = []): ?array
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }
        $result = self::$ormInstance->exec($sql, $bindings);
        if (is_array($result) && isset($result[0]) && is_array($result[0])) {
            return $result[0];
        }
        return null;
    }

    /**
     * Obtiene un solo valor de una consulta.
     *
     * @param string $sql
     * @param array<int, mixed> $bindings
     * @return mixed
     */
    public static function getCell(string $sql, array $bindings = [])
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }
        $result = self::$ormInstance->exec($sql, $bindings);
        if (is_array($result) && !empty($result) && is_array($result[0])) {
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
     * @param array<int, mixed> $bindings
     * @return array<int, self>
     */
    public static function findAll(string $table, ?string $conditions = null, array $bindings = []): array
    {
        if (!self::$ormInstance) {
            throw new \Exception("No ORM instance available. Call VersaModel::setORM() first.");
        }

        $queryBuilder = self::$ormInstance->table($table);

        if ($conditions) {
            // Intenta analizar condiciones simples como "columna operador ?"
            // Esto evita usar whereRaw para casos simples, lo que es más seguro y predecible.
            $simpleConditionPattern = '/^\s*([a-zA-Z0-9_\.]+)\s*(=|!=|<>|>|<|>=|<=|LIKE)\s*\?\s*$/';
            if (count($bindings) === 1 && preg_match($simpleConditionPattern, $conditions, $matches)) {
                $column = $matches[1];
                $operator = $matches[2];
                $queryBuilder->where($column, $operator, $bindings[0]);
            } else {
                // Si no es una condición simple, recurre a whereRaw como antes.
                $queryBuilder->whereRaw($conditions, $bindings);
            }
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