<?php

declare(strict_types=1);

namespace App\Models;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Modelo base para la aplicación.
 */
abstract class BaseModel extends VersaModel
{
    /**
     * Timestamps automáticos.
     */
    protected bool $timestamps = true;

    /**
     * Campos de timestamp.
     */
    protected array $dateFields = ['created_at', 'updated_at'];

    /**
     * Campos protegidos (permitir asignación masiva por defecto).
     */
    protected array $guarded = [];

    /* =============================================================
     * Helpers de acceso al ORM / QueryBuilder para evitar repetir
     * getGlobalORM() + validaciones en cada modelo hijo.
     * ============================================================= */
    /** ORM global (static). */
    public static function orm(): VersaORM
    {
        $orm = static::getGlobalORM();
        if (!$orm) {
            throw new \RuntimeException('No ORM instance available. Call VersaModel::setORM() first.');
        }
        return $orm;
    }
    /** ORM desde instancia. */
    protected function ormInstance(): VersaORM
    {
        /** @var VersaORM $orm */
        $orm = static::orm();
        return $orm;
    }
    /** QueryBuilder estático. */
    protected static function qb(string $table, ?string $modelClass = null): QueryBuilder
    {
        return static::orm()->table($table, $modelClass);
    }
    /** QueryBuilder desde instancia. */
    protected function query(string $table, ?string $modelClass = null): QueryBuilder
    {
        return static::orm()->table($table, $modelClass);
    }

    /**
     * Obtener todos los registros como array.
     */
    public static function allArray(): array
    {
        return static::findAll(static::getTableName());
    }

    /**
     * Obtener todos los registros como objetos VersaModel.
     */
    public static function all(): array
    {
        $tableName = static::getTableName();
        $records   = static::findAll($tableName);
        $objects   = [];

        foreach ($records as $record) {
            $obj = VersaModel::dispense($tableName);
            foreach ($record as $key => $value) {
                $obj->{$key} = $value;
            }
            $objects[] = $obj;
        }

        return $objects;
    }

    /**
     * Buscar por ID y devolver array.
     */
    public static function findArray(int $id): ?array
    {
        $tableName = static::getTableName();
        $result    = static::getAll("SELECT * FROM {$tableName} WHERE id = ?", [$id]);
        return $result ? $result[0] : null;
    }

    /**
     * Paginación simple.
     */
    public static function paginate(int $page = 1, int $perPage = 10): array
    {
        $tableName = static::getTableName();
        $offset    = ($page - 1) * $perPage;

        $items = static::getAll(
            "SELECT * FROM {$tableName} LIMIT ? OFFSET ?",
            [$perPage, $offset]
        );

        $totalResult = static::getAll("SELECT COUNT(*) as count FROM {$tableName}");
        $total       = $totalResult[0]['count'] ?? 0;

        return [
            'items'      => $items,
            'total'      => $total,
            'page'       => $page,
            'perPage'    => $perPage,
            'totalPages' => ceil($total / $perPage),
        ];
    }

    /**
     * Obtener nombre de tabla del modelo.
     */
    protected static function getTableName(): string
    {
        // Crear una instancia temporal solo para obtener el nombre de tabla
        $reflection = new \ReflectionClass(static::class);
        $instance   = $reflection->newInstanceWithoutConstructor();

        // Acceder a la propiedad protegida $table
        $tableProperty = $reflection->getProperty('table');
        $tableProperty->setAccessible(true);

        return $tableProperty->getValue($instance);
    }

    /**
     * Ejecutar comando SQL estático.
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
     * Validaciones básicas.
     */
    public function validate(): array
    {
        $errors = [];

        if (isset($this->rules)) {
            foreach ($this->rules as $field => $rules) {
                $value = $this->getAttribute($field);

                foreach ($rules as $rule) {
                    if ($rule === 'required' && empty($value)) {
                        $errors[$field][] = "El campo {$field} es requerido";
                    }

                    if (strpos($rule, 'min:') === 0) {
                        $min = (int) substr($rule, 4);
                        if (strlen($value) < $min) {
                            $errors[$field][] = "El campo {$field} debe tener al menos {$min} caracteres";
                        }
                    }

                    if (strpos($rule, 'max:') === 0) {
                        $max = (int) substr($rule, 4);
                        if (strlen($value) > $max) {
                            $errors[$field][] = "El campo {$field} no debe exceder {$max} caracteres";
                        }
                    }

                    if ($rule === 'email' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                        $errors[$field][] = "El campo {$field} debe ser un email válido";
                    }
                }
            }
        }

        return $errors;
    }


    /**
     * Validar consistencia del esquema entre modelo y base de datos.
     */
    public function validateSchemaConsistency(): array
    {
        $errors = [];

        try {
            $propertyTypes = static::definePropertyTypes();
            if (empty($propertyTypes)) {
                return []; // No hay tipos definidos, no validar
            }

            // Aquí se podría implementar la validación contra el esquema real de la BD
            // Por ahora, validamos que los tipos estén bien definidos en el modelo

            foreach ($propertyTypes as $property => $definition) {
                if (!isset($definition['type'])) {
                    $errors[] = "Propiedad '{$property}': tipo no definido";
                    continue;
                }

                $type       = $definition['type'];
                $validTypes = [
                    'int',
                    'string',
                    'text',
                    'bool',
                    'boolean',
                    'float',
                    'decimal',
                    'json',
                    'uuid',
                    'enum',
                    'set',
                    'date',
                    'datetime',
                    'timestamp',
                    'inet'
                ];

                if (!in_array($type, $validTypes)) {
                    $errors[] = "Propiedad '{$property}': tipo '{$type}' no es válido";
                }

                // Validar enumeraciones
                if ($type === 'enum' || $type === 'set') {
                    if (!isset($definition['values']) || !is_array($definition['values'])) {
                        $errors[] = "Propiedad '{$property}': tipo '{$type}' requiere definir 'values'";
                    }
                }

                // Validar longitud máxima para strings
                if ($type === 'string' && isset($definition['max_length'])) {
                    if (!is_int($definition['max_length']) || $definition['max_length'] <= 0) {
                        $errors[] = "Propiedad '{$property}': max_length debe ser un entero positivo";
                    }
                }
            }
        } catch (\Exception $e) {
            $errors[] = 'Error al validar esquema: ' . $e->getMessage();
        }

        return $errors;
    }

    /**
     * Validar y convertir valores según el tipo definido.
     */
    public function validateAndCastProperty(string $property, $value)
    {
        $propertyTypes = static::definePropertyTypes();

        if (!isset($propertyTypes[$property])) {
            return $value; // Sin validación si no está definido el tipo
        }

        $definition = $propertyTypes[$property];
        $type       = $definition['type'];
        $nullable   = $definition['nullable'] ?? true;

        // Verificar nulos
        if ($value === null) {
            if (!$nullable) {
                throw new \InvalidArgumentException("La propiedad '{$property}' no puede ser null");
            }
            return null;
        }

        // Conversión según tipo
        switch ($type) {
            case 'int':
                return (int) $value;

            case 'float':
            case 'decimal':
                return (float) $value;

            case 'bool':
            case 'boolean':
                return $this->castToBoolean($value);

            case 'string':
                $stringValue = (string) $value;
                if (isset($definition['max_length']) && strlen($stringValue) > $definition['max_length']) {
                    throw new \InvalidArgumentException("La propiedad '{$property}' excede la longitud máxima de {$definition['max_length']} caracteres");
                }
                return $stringValue;

            case 'text':
                return (string) $value;

            case 'json':
                if (is_array($value) || is_object($value)) {
                    return json_encode($value);
                }
                return $value;

            case 'enum':
                $stringValue = (string) $value;
                if (!in_array($stringValue, $definition['values'])) {
                    $allowedValues = implode(', ', $definition['values']);
                    throw new \InvalidArgumentException("La propiedad '{$property}' debe ser uno de: {$allowedValues}");
                }
                return $stringValue;

            case 'set':
                if (is_array($value)) {
                    $value = implode(',', $value);
                }
                $values = explode(',', (string) $value);
                foreach ($values as $val) {
                    $val = trim($val);
                    if (!in_array($val, $definition['values'])) {
                        $allowedValues = implode(', ', $definition['values']);
                        throw new \InvalidArgumentException("Valor '{$val}' en propiedad '{$property}' no es válido. Valores permitidos: {$allowedValues}");
                    }
                }
                return (string) $value;

            case 'uuid':
                if (!$this->isValidUUID($value)) {
                    throw new \InvalidArgumentException("La propiedad '{$property}' debe ser un UUID válido");
                }
                return (string) $value;

            case 'date':
            case 'datetime':
            case 'timestamp':
                // Si ya es un DateTime, convertir a string
                if ($value instanceof \DateTime) {
                    return $value->format('Y-m-d H:i:s');
                }
                // Si es timestamp, convertir
                if (is_numeric($value)) {
                    return date('Y-m-d H:i:s', (int) $value);
                }
                return (string) $value;

            case 'inet':
                if (!filter_var($value, FILTER_VALIDATE_IP)) {
                    throw new \InvalidArgumentException("La propiedad '{$property}' debe ser una dirección IP válida");
                }
                return (string) $value;

            default:
                return $value;
        }
    }

    /**
     * Convertir valor a booleano de manera inteligente.
     */
    private function castToBoolean($value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_numeric($value)) {
            return (bool) $value;
        }

        if (is_string($value)) {
            $value = strtolower(trim($value));
            return in_array($value, ['true', '1', 'yes', 'on', 'y']);
        }

        return (bool) $value;
    }

    /**
     * Validar formato UUID.
     */
    private function isValidUUID(string $uuid): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuid) === 1;
    }

    /**
     * Método para definir tipos de propiedades (debe ser sobrescrito en modelos hijos).
     */
    public static function definePropertyTypes(): array
    {
        return [];
    }

    /**
     * Normalizar campos opcionales que vienen vacíos desde formularios.
     * Convierte cadenas vacías a null para campos que deberían ser null en DB.
     */
    protected function normalizeOptionalFields(array &$attributes, array $optionalFields): void
    {
        foreach ($optionalFields as $field) {
            if (isset($attributes[$field]) && ($attributes[$field] === '' || $attributes[$field] === null)) {
                $attributes[$field] = null;
            }
        }
    }

    /**
     * Normalizar campos de fecha opcionales.
     */
    protected function normalizeOptionalDateFields(array &$attributes, array $dateFields): void
    {
        foreach ($dateFields as $field) {
            if (isset($attributes[$field]) && ($attributes[$field] === '' || $attributes[$field] === null)) {
                $attributes[$field] = null;
            }
        }
    }
}
