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
     * Constructor
     */
    public function __construct()
    {
        // Usar la tabla definida en la clase o inferir del nombre de la clase
        $tableName = $this->table ?? strtolower(basename(str_replace('\\', '/', static::class))) . 's';

        // Usar la instancia global del ORM
        $orm = parent::getGlobalORM();
        if ($orm) {
            parent::__construct($tableName, $orm);
        } else {
            // Si no hay ORM, solo inicializar las propiedades básicas
            $this->table = $tableName;
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
        return $this->getOrm();
    }

    /**
     * Crea un nuevo modelo (factory method)
     * Utiliza VersaModel::dispense() para crear instancias manipulables
     */
    public static function create(array $data): static
    {
        // Usar el ORM global directamente
        $orm = static::getGlobalORM();
        if (!$orm) {
            throw new \Exception('No ORM instance available. Make sure VersaORM is initialized.');
        }

        // Asegurar que el ORM estático esté configurado
        VersaModel::setORM($orm);

        $instance = new static();
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
        $tableName = $instance->getTableName();
        $primaryKey = $instance->getPrimaryKey();

        $orm = parent::getGlobalORM();
        if (!$orm) {
            throw new \Exception('ORM instance not initialized. Call VersaModel::setORM() first.');
        }

        $result = $orm->table($tableName)
            ->where($primaryKey, '=', $id)
            ->findOne();

        if ($result) {
            // Si $result es instancia de VersaModel, usar export()
            if (method_exists($result, 'export')) {
                $attributes = $result->export();
            } elseif (is_array($result)) {
                $attributes = $result;
            } else {
                $attributes = [];
            }
            $model = new static();
            $model->loadInstance($attributes);
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
        $tableName = $instance->getTableName();
        $primaryKey = $instance->getPrimaryKey();

        $orm = parent::getGlobalORM();
        if (!$orm) {
            throw new \Exception('ORM instance not initialized. Call VersaModel::setORM() first.');
        }

        return $orm->table($tableName)->orderBy($primaryKey, 'DESC')->get();
    }

    /**
     * Obtiene todos los registros como array asociativo (no objetos)
     *
     * @return array<int, array<string, mixed>>
     */
    public static function allArray(): array
    {
        $instance = new static();
        $tableName = $instance->getTableName();
        $primaryKey = $instance->getPrimaryKey();

        $orm = parent::getGlobalORM();
        if (!$orm) {
            throw new \Exception('ORM instance not initialized. Call VersaModel::setORM() first.');
        }

        return $orm->table($tableName)->orderBy($primaryKey, 'DESC')->get();
    }

    /**
     * Obtiene el nombre de tabla de la clase sin instanciar
     */
    private function getTableName(): string
    {
        return $this->table ?? strtolower(basename(str_replace('\\', '/', static::class))) . 's';
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
     * Busca registros with condiciones
     */
    public static function where(string $column, string $operator, $value): array
    {
        $instance = new static();
        $orm = static::getGlobalORM();
        if (!$orm) {
            throw new \Exception('No ORM instance available.');
        }
        $sql = "SELECT * FROM {$instance->table} WHERE {$column} {$operator} ? ORDER BY {$instance->primaryKey} DESC";
        $results = $orm->exec($sql, [$value]);

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
     * Busca registros con condiciones y devuelve arrays asociativos (no objetos)
     *
     * @return array<int, array<string, mixed>>
     */
    public static function whereArray(string $column, string $operator, $value): array
    {
        $instance = new static();
        $tableName = $instance->getTableName();
        $primaryKey = $instance->getPrimaryKey();

        $orm = parent::getGlobalORM();
        if (!$orm) {
            throw new \Exception('ORM instance not initialized. Call VersaModel::setORM() first.');
        }

        $sql = "SELECT * FROM {$tableName} WHERE {$column} {$operator} ? ORDER BY {$primaryKey} DESC";
        return $orm->exec($sql, [$value]);
    }

    /**
     * Actualiza el modelo current de manera segura
     * Sobrescribe el método padre para mantener compatibilidad
     * pero usa la implementación estándar de VersaModel
     */
    public function updateSafe(array $data): bool
    {
        try {
            $this->update($data); // Usa el método padre que retorna self
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
     * Búsqueda case-insensitive en múltiples campos, devuelve arrays asociativos (no objetos)
     *
     * @return array<int, array<string, mixed>>
     */
    public static function searchArray(string $term, array $fields = []): array
    {
        $instance = new static();
        if (empty($fields)) {
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
     * Paginación que devuelve arrays asociativos (no objetos) en 'data'
     *
     * @return array{data: array<int, array<string, mixed>>, total: int, page: int, per_page: int, total_pages: int}
     */
    public static function paginateArray(int $page = 1, int $perPage = 10): array
    {
        $instance = new static();
        $offset = ($page - 1) * $perPage;
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
            'total_pages' => (int)ceil($total / $perPage)
        ];
    }

    /**
     * Validación básica (debe ser implementada en cada modelo)
     */
    public function validate(): array
    {
        return []; // Retorna array vacío si no hay errores
    }
}
