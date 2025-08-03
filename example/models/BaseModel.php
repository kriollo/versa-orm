<?php

namespace App\Models;

use VersaORM\VersaModel;

/**
 * Modelo base para la aplicación
 */
abstract class BaseModel extends VersaModel
{
    /**
     * Timestamps automáticos
     */
    protected bool $timestamps = true;

    /**
     * Campos de timestamp
     */
    protected array $dateFields = ['created_at', 'updated_at'];

    /**
     * Campos protegidos (permitir asignación masiva por defecto)
     */
    protected array $guarded = [];

    /**
     * Obtener todos los registros como array
     */
    public static function allArray(): array
    {
        return static::findAll(static::getTableName());
    }

    /**
     * Obtener todos los registros como objetos VersaModel
     */
    public static function all(): array
    {
        $tableName = static::getTableName();
        $records = static::findAll($tableName);
        $objects = [];

        foreach ($records as $record) {
            $obj = VersaModel::dispense($tableName);
            foreach ($record as $key => $value) {
                $obj->$key = $value;
            }
            $objects[] = $obj;
        }

        return $objects;
    }

    /**
     * Buscar por ID y devolver array
     */
    public static function findArray(int $id): ?array
    {
        $tableName = static::getTableName();
        $result = static::getAll("SELECT * FROM {$tableName} WHERE id = ?", [$id]);
        return $result ? $result[0] : null;
    }

    /**
     * Paginación simple
     */
    public static function paginate(int $page = 1, int $perPage = 10): array
    {
        $tableName = static::getTableName();
        $offset = ($page - 1) * $perPage;

        $items = static::getAll(
            "SELECT * FROM {$tableName} LIMIT ? OFFSET ?",
            [$perPage, $offset]
        );

        $totalResult = static::getAll("SELECT COUNT(*) as count FROM {$tableName}");
        $total = $totalResult[0]['count'] ?? 0;

        return [
            'items' => $items,
            'total' => $total,
            'page' => $page,
            'perPage' => $perPage,
            'totalPages' => ceil($total / $perPage)
        ];
    }

    /**
     * Obtener nombre de tabla del modelo
     */
    protected static function getTableName(): string
    {
        // Crear una instancia temporal solo para obtener el nombre de tabla
        $reflection = new \ReflectionClass(static::class);
        $instance = $reflection->newInstanceWithoutConstructor();

        // Acceder a la propiedad protegida $table
        $tableProperty = $reflection->getProperty('table');
        $tableProperty->setAccessible(true);

        return $tableProperty->getValue($instance);
    }

    /**
     * Ejecutar comando SQL estático
     */
    protected static function execSql(string $sql, array $bindings = []): mixed
    {
        $orm = static::getGlobalORM();
        if (!$orm) {
            throw new \Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }
        return $orm->exec($sql, $bindings);
    }

    /**
     * Validaciones básicas
     */
    public function validate(): array
    {
        $errors = [];

        if (isset($this->rules)) {
            foreach ($this->rules as $field => $rules) {
                $value = $this->getAttribute($field);

                foreach ($rules as $rule) {
                    if ($rule === 'required' && empty($value)) {
                        $errors[$field][] = "El campo $field es requerido";
                    }

                    if (strpos($rule, 'min:') === 0) {
                        $min = (int) substr($rule, 4);
                        if (strlen($value) < $min) {
                            $errors[$field][] = "El campo $field debe tener al menos $min caracteres";
                        }
                    }

                    if (strpos($rule, 'max:') === 0) {
                        $max = (int) substr($rule, 4);
                        if (strlen($value) > $max) {
                            $errors[$field][] = "El campo $field no debe exceder $max caracteres";
                        }
                    }

                    if ($rule === 'email' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                        $errors[$field][] = "El campo $field debe ser un email válido";
                    }
                }
            }
        }

        return $errors;
    }

    /**
     * Guardar con validación
     */
    public function save(): bool
    {
        $errors = $this->validate();
        if (!empty($errors)) {
            throw new \Exception('Errores de validación: ' . json_encode($errors));
        }

        try {
            $this->store();
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }
}
