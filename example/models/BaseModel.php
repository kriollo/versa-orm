<?php

namespace Example\Models;

use VersaORM\Traits\VersaORMTrait;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Clase base estándar para todos los modelos del proyecto
 *
 * PROPÓSITO: Proporciona funcionalidad común y estandarizada
 * ARQUITECTURA:
 * - Extiende VersaModel (base ActiveRecord del ORM)
 * - Proporciona métodos estáticos de conveniencia para consultas comunes
 * - Maneja instancias singleton de ORM por clase para eficiencia
 * - Funcionalidad común: validación, serialización, búsqueda, paginación
 */
abstract class BaseModel extends VersaModel
{
    use VersaORMTrait;

    /**
     * Nombre de la tabla (debe ser definido en cada modelo hijo)
     * @var string
     */
    protected string $table;

    /**
     * Clave primaria (por defecto 'id')
     * @var string
     */
    protected string $primaryKey = 'id';

    /**
     * Campos que se pueden asignar masivamente
     * @var array
     */
    protected array $fillable = [];

    /**
     * Campos que están ocultos en la serialización
     * @var array
     */
    protected array $hidden = [];

    /**
     * Instancia de ORM compartida (singleton por clase)
     * @var array<string, VersaORM>
     */
    private static array $ormInstances = [];

    public function __construct()
    {
        // Obtener instancia de ORM reutilizable por clase
        $className = static::class;
        if (!isset(self::$ormInstances[$className])) {
            $this->connectORM();
            self::$ormInstances[$className] = $this->db;
        } else {
            $this->db = self::$ormInstances[$className];
        }

        // Inicializar el modelo base con la tabla y ORM
        if (!empty($this->table)) {
            parent::__construct($this->table, $this->db);
        }
    }

    /**
     * Obtiene el nombre de la tabla
     */
    public function getTable(): string
    {
        return $this->table;
    }

    /**
     * Obtiene la clave primaria
     */
    public function getPrimaryKey(): string
    {
        return $this->primaryKey;
    }

    /**
     * Obtiene la instancia del ORM
     */
    public function getORM(): VersaORM
    {
        return $this->db;
    }

    /**
     * Crea un nuevo modelo (factory method)
     * Utiliza VersaModel::dispense() para crear instancias manipulables
     */
    public static function create(array $data): static
    {
        $instance = new static();
        // Asegurar que el ORM estático esté configurado
        VersaModel::setORM($instance->db);
        $model = VersaModel::dispense($instance->table);

        // Asignar solo campos permitidos
        foreach ($data as $key => $value) {
            if (empty($instance->fillable) || in_array($key, $instance->fillable)) {
                $model->$key = $value;
            }
        }

        $model->store();
        return self::find($model->id);
    }

    /**
     * Busca un modelo por ID
     */
    public static function find($id): ?static
    {
        $instance = new static();
        $result = $instance->db->table($instance->table)
            ->where($instance->primaryKey, '=', $id)
            ->findOne();

        if ($result) {
            $model = new static();
            $model->loadInstance($result->export());
            return $model;
        }

        return null;
    }

    /**
     * Obtiene todos los registros
     */
    public static function all(): array
    {
        $instance = new static();
        $results = $instance->db->table($instance->table)->orderBy($instance->primaryKey, 'DESC')->get();

        return $results;
    }

    /**
     * Cuenta todos los registros de esta tabla
     */
    public static function countAll(): int
    {
        $instance = new static();
        return $instance->db->table($instance->table)->count();
    }

    /**
     * Busca registros con condiciones
     */
    public static function where(string $column, string $operator, $value): array
    {
        $instance = new static();
        $sql = "SELECT * FROM {$instance->table} WHERE {$column} {$operator} ? ORDER BY {$instance->primaryKey} DESC";
        $results = $instance->db->exec($sql, [$value]);

        // Convertir resultados a modelos de la clase correcta
        $models = [];
        foreach ($results as $result) {
            $model = new static();
            $model->loadInstance($result);
            $models[] = $model;
        }

        return $models;
    }

    /**
     * Actualiza el modelo actual
     */
    public function update(array $data): bool
    {
        foreach ($data as $key => $value) {
            if (empty($this->fillable) || in_array($key, $this->fillable)) {
                $this->$key = $value;
            }
        }

        try {
            $this->store();
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Elimina el modelo actual
     */
    public function delete(): bool
    {
        try {
            $this->trash();
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Exporta el modelo excluyendo campos ocultos
     */
    public function toArray(): array
    {
        $data = $this->export();

        if (!empty($this->hidden)) {
            foreach ($this->hidden as $field) {
                unset($data[$field]);
            }
        }

        return $data;
    }

    /**
     * Convierte a JSON
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_UNESCAPED_UNICODE);
    }

    /**
     * Búsqueda case-insensitive en múltiples campos
     */
    public static function search(string $term, array $fields = []): array
    {
        $instance = new static();

        if (empty($fields)) {
            // Si no se especifican campos, buscar en todos los fillable
            $fields = $instance->fillable;
        }

        if (empty($fields)) {
            return [];
        }

        $searchLower = strtolower($term);
        $conditions = [];
        $bindings = [];

        foreach ($fields as $field) {
            $conditions[] = "LOWER($field) LIKE ?";
            $bindings[] = "%$searchLower%";
        }

        $result = $instance->db->table($instance->table)
            ->whereRaw(implode(' OR ', $conditions), $bindings)
            ->orderBy($instance->primaryKey, 'DESC')->get();

        return $result;
    }

    /**
     * Paginación
     */
    public static function paginate(int $page = 1, int $perPage = 10): array
    {
        $instance = new static();
        $offset = ($page - 1) * $perPage;

        // $sql = "SELECT * FROM {$instance->table} ORDER BY {$instance->primaryKey} DESC LIMIT ? OFFSET ?";
        // $results = $instance->db->exec($sql, [$perPage, $offset]);

        $results = $instance->db->table($instance->table)
            ->orderBy($instance->primaryKey, 'DESC')
            ->limit($perPage)
            ->offset($offset)
            ->getAll();

        $total = $instance->db->table($instance->table)->count();

        return [
            'data' => $results,
            'total' => $total,
            'page' => $page,
            'per_page' => $perPage,
            'total_pages' => ceil($total / $perPage)
        ];
    }

    /**
     * Validación básica (debe ser implementada en cada modelo)
     */
    public function validate(): array
    {
        return []; // Retorna array vacío si no hay errores
    }

    /**
     * Limpieza al final del ciclo de vida de la clase
     */
    public static function closeConnections(): void
    {
        foreach (self::$ormInstances as $orm) {
            $orm->disconnect();
        }
        self::$ormInstances = [];
    }
}
