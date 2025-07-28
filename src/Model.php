<?php

declare(strict_types=1);

namespace VersaORM;

/**
 * VersaORMModel - Clase de modelo ORM para VersaORM
 *
 * @package VersaORM
 * @version 1.0.0
 * @author VersaORM Team
 * @license MIT
 */
class Model
{
    private string $table;
    private $orm; // Puede ser array (config) o instancia de VersaORM
    private array $attributes = [];
    private string $primaryKey = 'id';
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
     * @param mixed $id
     * @param string $pk
     * @return self
     */
    public function loadInstance($id, string $pk = 'id'): self
    {
        $orm = $this->orm ?? self::$ormInstance;
        if (!($orm instanceof VersaORM)) {
            throw new \Exception("No ORM instance available for load operation");
        }

        $data = $orm->exec("SELECT * FROM {$this->table} WHERE {$pk} = ?", [$id]);
        if (!empty($data)) {
            $this->attributes = $data[0];
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
            
            // Obtener el último registro insertado por este modelo
            $result = $orm->exec("SELECT * FROM {$this->table} ORDER BY id DESC LIMIT 1");
            if (!empty($result)) {
                $this->attributes = $result[0]; // Actualizar con todos los datos del registro
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
     * Convertir el modelo a un array.
     *
     * @return array
     */
    public function toArray(): array
    {
        return $this->attributes;
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
}
