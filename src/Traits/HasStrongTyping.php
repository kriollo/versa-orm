<?php

declare(strict_types=1);

namespace VersaORM\Traits;

use VersaORM\VersaORMException;

/**
 * Trait que proporciona funcionalidad de tipado fuerte para modelos.
 *
 * Permite definir tipos PHP específicos para propiedades del modelo y
 * automatizar la conversión entre tipos PHP y tipos de base de datos.
 */
trait HasStrongTyping
{
    /**
     * Cache de tipos de propiedades para mejorar rendimiento.
     *
     * @var array<string, array<string, mixed>>|null
     */
    private static ?array $cachedPropertyTypes = null;

    /**
     * Cache de esquema de base de datos para validación de consistencia.
     *
     * @var array<string, mixed>|null
     */
    private ?array $databaseSchemaCache = null;

    /**
     * Mutadores personalizados para propiedades específicas.
     *
     * @var array<string, callable>
     */
    protected array $mutators = [];

    /**
     * Accesorios personalizados para propiedades específicas.
     *
     * @var array<string, callable>
     */
    protected array $accessors = [];

    /**
     * Tipos de casting automático soportados.
     *
     * @var array<string, string>
     */
    private static array $supportedCasts = [
        'int' => 'integer',
        'integer' => 'integer',
        'real' => 'float',
        'float' => 'float',
        'double' => 'float',
        'decimal' => 'float',
        'string' => 'string',
        'bool' => 'boolean',
        'boolean' => 'boolean',
        'object' => 'object',
        'array' => 'array',
        'collection' => 'array',
        'date' => 'datetime',
        'datetime' => 'datetime',
        'timestamp' => 'datetime',
        'json' => 'json',
        'uuid' => 'uuid',
        'enum' => 'enum',
        'set' => 'set',
        'blob' => 'blob',
        'inet' => 'inet',
    ];

    /**
     * Obtiene los tipos de propiedades definidos para el modelo.
     *
     * Los modelos deben sobrescribir este método para definir sus tipos.
     *
     * Ejemplo:
     * ```php
     * public static function getPropertyTypes(): array
     * {
     *     return [
     *         'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
     *         'name' => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
     *         'email' => ['type' => 'string', 'max_length' => 255, 'nullable' => false, 'unique' => true],
     *         'settings' => ['type' => 'json', 'nullable' => true],
     *         'uuid' => ['type' => 'uuid', 'nullable' => false],
     *         'status' => ['type' => 'enum', 'values' => ['active', 'inactive'], 'default' => 'active'],
     *         'tags' => ['type' => 'set', 'values' => ['work', 'personal', 'urgent']],
     *         'created_at' => ['type' => 'datetime', 'nullable' => false],
     *         'updated_at' => ['type' => 'datetime', 'nullable' => true],
     *     ];
     * }
     * ```
     *
     * @return array<string, array<string, mixed>>
     */
    public static function getPropertyTypes(): array
    {
        if (self::$cachedPropertyTypes === null) {
            // Verificar si el método existe en la clase actual usando reflection
            $calledClass = get_called_class();
            $reflectionClass = new \ReflectionClass($calledClass);
            if ($reflectionClass->hasMethod('definePropertyTypes')) {
                $method = $reflectionClass->getMethod('definePropertyTypes');
                if ($method->isStatic()) {
                    /**
                     * @var array<string, array<string, mixed>> $result
                     */
                    $result = $method->invoke(null);
                    self::$cachedPropertyTypes = $result;
                } else {
                    self::$cachedPropertyTypes = [];
                }
            } else {
                self::$cachedPropertyTypes = [];
            }
        }

        return self::$cachedPropertyTypes;
    }

    /**
     * Define los tipos de propiedades del modelo.
     * Este método debe ser implementado por las clases que usen este trait.
     * No proporciona implementación por defecto para evitar conflictos.
     *
     * @return array<string, array<string, mixed>>
     */
    // NOTA: Este método debe ser implementado en las clases que usen el trait
    // protected static function definePropertyTypes(): array;

    /**
     * Convierte un valor de la base de datos al tipo PHP apropiado.
     *
     * @param  string $property
     * @param  mixed  $value
     * @return mixed
     * @throws VersaORMException
     */
    public function castToPhpType(string $property, $value)
    {
        if ($value === null) {
            return null;
        }

        $propertyTypes = static::getPropertyTypes();

        if (!isset($propertyTypes[$property])) {
            return $value; // Sin conversión si no hay tipo definido
        }

        $typeDefinition = $propertyTypes[$property];
        $type = $typeDefinition['type'] ?? 'string';

        try {
            switch ($type) {
                case 'int':
                case 'integer':
                    return is_numeric($value) ? (int) $value : 0;

                case 'float':
                case 'real':
                case 'double':
                case 'decimal':
                    return is_numeric($value) ? (float) $value : 0.0;

                case 'string':
                    return is_scalar($value) ? (string) $value : '';

                case 'bool':
                case 'boolean':
                    if (is_string($value)) {
                        return in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
                    }
                    return (bool) $value;

                case 'array':
                case 'collection':
                    if (is_string($value)) {
                        $decoded = json_decode($value, true);
                        return $decoded !== null ? $decoded : [];
                    }
                    return is_array($value) ? $value : [$value];

                case 'json':
                    if (is_string($value)) {
                        $decoded = json_decode($value, true);
                        if (json_last_error() !== JSON_ERROR_NONE) {
                            throw new VersaORMException("Invalid JSON for property {$property}: " . json_last_error_msg());
                        }
                        return $decoded;
                    }
                    return $value;

                case 'uuid':
                    $uuidValue = (string) $value;
                    if (!$this->isValidUuid($uuidValue)) {
                        throw new VersaORMException("Invalid UUID format for property {$property}: {$uuidValue}");
                    }
                    return $uuidValue;

                case 'datetime':
                case 'date':
                case 'timestamp':
                    if (is_string($value)) {
                        return new \DateTime($value);
                    } elseif ($value instanceof \DateTime) {
                        return $value;
                    }
                    return new \DateTime('@' . (int) $value);

                case 'enum':
                    $enumValue = (string) $value;
                    $allowedValues = $typeDefinition['values'] ?? [];
                    if (!empty($allowedValues) && !in_array($enumValue, $allowedValues, true)) {
                        throw new VersaORMException("Invalid enum value for property {$property}. Allowed: " . implode(', ', $allowedValues));
                    }
                    return $enumValue;

                case 'set':
                    if (is_string($value)) {
                        // Try to decode as JSON first
                        $decoded = json_decode($value, true);
                        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                            $setValue = $decoded;
                        } else {
                            // Fall back to comma-separated values
                            $setValue = explode(',', $value);
                        }
                    } else {
                        $setValue = (array) $value;
                    }

                    $allowedValues = $typeDefinition['values'] ?? [];
                    if (!empty($allowedValues)) {
                        foreach ($setValue as $val) {
                            if (!in_array($val, $allowedValues, true)) {
                                throw new VersaORMException("Invalid set value '{$val}' for property {$property}. Allowed: " . implode(', ', $allowedValues));
                            }
                        }
                    }
                    return $setValue;

                case 'blob':
                    return $value; // Los BLOBs se mantienen como están

                case 'inet':
                    $inetValue = (string) $value;
                    if (!filter_var($inetValue, FILTER_VALIDATE_IP)) {
                        throw new VersaORMException("Invalid IP address for property {$property}: {$inetValue}");
                    }
                    return $inetValue;

                default:
                    return $value;
            }
        } catch (\Exception $e) {
            throw new VersaORMException(
                "Error casting property {$property} to PHP type {$type}: " . $e->getMessage(),
                'TYPE_CASTING_ERROR'
            );
        }
    }

    /**
     * Convierte un valor PHP al formato apropiado para la base de datos.
     *
     * @param  string $property
     * @param  mixed  $value
     * @return mixed
     * @throws VersaORMException
     */
    public function castToDatabaseType(string $property, $value)
    {
        if ($value === null) {
            return null;
        }

        $propertyTypes = static::getPropertyTypes();

        if (!isset($propertyTypes[$property])) {
            return $value; // Sin conversión si no hay tipo definido
        }

        $typeDefinition = $propertyTypes[$property];
        $type = $typeDefinition['type'] ?? 'string';

        try {
            switch ($type) {
                case 'int':
                case 'integer':
                    return (int) $value;

                case 'float':
                case 'real':
                case 'double':
                case 'decimal':
                    return (float) $value;

                case 'string':
                    $stringValue = (string) $value;
                    $maxLength = $typeDefinition['max_length'] ?? null;
                    if ($maxLength && strlen($stringValue) > $maxLength) {
                        throw new VersaORMException("String too long for property {$property}. Max: {$maxLength}, got: " . strlen($stringValue));
                    }
                    return $stringValue;

                case 'bool':
                case 'boolean':
                    return (bool) $value ? 1 : 0;

                case 'array':
                case 'collection':
                case 'json':
                    return json_encode($value, JSON_UNESCAPED_UNICODE);

                case 'uuid':
                    $uuidValue = (string) $value;
                    if (!$this->isValidUuid($uuidValue)) {
                        throw new VersaORMException("Invalid UUID format for property {$property}: {$uuidValue}");
                    }
                    return $uuidValue;

                case 'datetime':
                case 'date':
                case 'timestamp':
                    if ($value instanceof \DateTime) {
                        return $value->format('Y-m-d H:i:s');
                    } elseif (is_string($value)) {
                        return (new \DateTime($value))->format('Y-m-d H:i:s');
                    }
                    return date('Y-m-d H:i:s', (int) $value);

                case 'enum':
                    $enumValue = (string) $value;
                    $allowedValues = $typeDefinition['values'] ?? [];
                    if (!empty($allowedValues) && !in_array($enumValue, $allowedValues, true)) {
                        throw new VersaORMException("Invalid enum value for property {$property}. Allowed: " . implode(', ', $allowedValues));
                    }
                    return $enumValue;

                case 'set':
                    $setValue = is_array($value) ? $value : [$value];
                    $allowedValues = $typeDefinition['values'] ?? [];
                    if (!empty($allowedValues)) {
                        foreach ($setValue as $val) {
                            if (!in_array($val, $allowedValues, true)) {
                                throw new VersaORMException("Invalid set value '{$val}' for property {$property}. Allowed: " . implode(', ', $allowedValues));
                            }
                        }
                    }
                    return implode(',', $setValue);

                case 'blob':
                    return $value; // Los BLOBs se mantienen como están

                case 'inet':
                    $inetValue = (string) $value;
                    if (!filter_var($inetValue, FILTER_VALIDATE_IP)) {
                        throw new VersaORMException("Invalid IP address for property {$property}: {$inetValue}");
                    }
                    return $inetValue;

                default:
                    return $value;
            }
        } catch (\Exception $e) {
            throw new VersaORMException(
                "Error casting property {$property} to database type {$type}: " . $e->getMessage(),
                'DATABASE_CASTING_ERROR'
            );
        }
    }

    /**
     * Valida que el esquema del modelo sea consistente con la base de datos
     * y muestra advertencias en consola si difiere.
     *
     * @return array<string> Array de errores de consistencia
     */
    public function validateSchemaConsistency(): array
    {
        $errors = [];
        $propertyTypes = static::getPropertyTypes();

        try {
            // Validar que tenemos una instancia de VersaORM
            if (!($this->orm instanceof \VersaORM\VersaORM)) {
                $errors[] = 'Se requiere una instancia válida de VersaORM para validar el esquema';
                return $errors;
            }

            // Obtener esquema real de la base de datos
            $schemaInfo = $this->orm->schema('columns', $this->table);

            if (empty($schemaInfo)) {
                $errors[] = "No se pudo obtener información de esquema para la tabla '{$this->table}'";
                return $errors;
            }

            $dbColumns = [];
            foreach ($schemaInfo as $column) {
                $dbColumns[strtolower($column['column_name'])] = $column;
            }

            // Verificar propiedades del modelo vs esquema DB
            foreach ($propertyTypes as $property => $definition) {
                $columnName = strtolower($property);

                if (!isset($dbColumns[$columnName])) {
                    $warning = "⚠️  ADVERTENCIA: La propiedad '{$property}' no existe en la base de datos";
                    $errors[] = $warning;
                    if (php_sapi_name() === 'cli') {
                        echo "\033[33m{$warning}\033[0m\n";
                    }
                    continue;
                }

                $dbColumn = $dbColumns[$columnName];
                $dbType = strtolower($dbColumn['data_type']);
                $modelType = strtolower($definition['type']);

                // Mapear tipos de base de datos a tipos del modelo
                $typeMapping = [
                    'varchar' => 'string',
                    'char' => 'string',
                    'text' => 'string',
                    'longtext' => 'text',
                    'int' => 'int',
                    'integer' => 'int',
                    'bigint' => 'int',
                    'smallint' => 'int',
                    'tinyint' => 'boolean',
                    'decimal' => 'decimal',
                    'numeric' => 'decimal',
                    'float' => 'float',
                    'double' => 'float',
                    'real' => 'float',
                    'date' => 'date',
                    'datetime' => 'datetime',
                    'timestamp' => 'datetime',
                    'time' => 'time',
                    'json' => 'json',
                    'jsonb' => 'json',
                    'blob' => 'blob',
                    'longblob' => 'blob',
                    'binary' => 'binary',
                    'varbinary' => 'binary',
                    'enum' => 'enum',
                    'set' => 'set',
                    'uuid' => 'uuid',
                    'inet' => 'inet',
                ];

                $expectedType = $typeMapping[$dbType] ?? $dbType;

                if ($expectedType !== $modelType && !$this->isCompatibleType($expectedType, $modelType)) {
                    $warning = "⚠️  INCONSISTENCIA: '{$property}' - DB: {$dbType} ({$expectedType}) vs Modelo: {$modelType}";
                    $errors[] = $warning;
                    if (php_sapi_name() === 'cli') {
                        echo "\033[31m{$warning}\033[0m\n";
                    }
                }

                // Verificar nullabilidad
                $isNullable = strtolower($dbColumn['is_nullable'] ?? 'no') === 'yes';
                $modelNullable = $definition['nullable'] ?? false;

                if ($isNullable !== $modelNullable) {
                    $warning = "⚠️  NULLABILIDAD: '{$property}' - DB permite NULL: " .
                        ($isNullable ? 'Sí' : 'No') . ' vs Modelo: ' .
                        ($modelNullable ? 'Sí' : 'No');
                    $errors[] = $warning;
                    if (php_sapi_name() === 'cli') {
                        echo "\033[33m{$warning}\033[0m\n";
                    }
                }
            }

            // Verificar columnas de DB que no están en el modelo
            foreach ($dbColumns as $columnName => $column) {
                if (!isset($propertyTypes[$columnName])) {
                    $warning = "💡 INFO: Columna '{$columnName}' existe en DB pero no está definida en el modelo";
                    $errors[] = $warning;
                    if (php_sapi_name() === 'cli') {
                        echo "\033[36m{$warning}\033[0m\n";
                    }
                }
            }
        } catch (\Exception $e) {
            $errors[] = 'Error al validar esquema: ' . $e->getMessage();
        }

        return $errors;
    }

    /**
     * Verifica si dos tipos son compatibles.
     */
    private function isCompatibleType(string $dbType, string $modelType): bool
    {
        $compatibleTypes = [
            'string' => ['text', 'varchar', 'char'],
            'text' => ['string', 'varchar', 'char'],
            'int' => ['integer', 'bigint', 'smallint'],
            'integer' => ['int', 'bigint', 'smallint'],
            'float' => ['double', 'real', 'decimal'],
            'decimal' => ['float', 'double', 'numeric'],
            'boolean' => ['tinyint', 'bit'],
            'datetime' => ['timestamp', 'date'],
            'timestamp' => ['datetime'],
        ];

        return in_array($modelType, $compatibleTypes[$dbType] ?? []);
    }

    /**
     * Obtiene el esquema de la base de datos para la tabla del modelo.
     *
     * @return array<string, mixed>
     * @throws VersaORMException
     */
    private function getDatabaseSchema(): array
    {
        if ($this->databaseSchemaCache !== null) {
            return $this->databaseSchemaCache;
        }

        try {
            $schema = $this->getTableValidationSchema();
            $this->databaseSchemaCache = $schema;
            return $schema;
        } catch (\Exception $e) {
            throw new VersaORMException('Could not retrieve database schema: ' . $e->getMessage());
        }
    }

    /**
     * Obtiene los mutadores definidos para las propiedades.
     *
     * @return array<string, callable>
     */
    public function getMutators(): array
    {
        return $this->mutators;
    }

    /**
     * Obtiene los accesorios definidos para las propiedades.
     *
     * @return array<string, callable>
     */
    public function getAccessors(): array
    {
        return $this->accessors;
    }

    /**
     * Aplica mutadores al establecer un valor de atributo.
     *
     * @param  string $key
     * @param  mixed  $value
     * @return mixed
     */
    protected function applyMutator(string $key, $value)
    {
        if (isset($this->mutators[$key])) {
            return call_user_func($this->mutators[$key], $value);
        }

        // Aplicar casting automático
        return $this->castToDatabaseType($key, $value);
    }

    /**
     * Aplica accesorios al obtener un valor de atributo.
     *
     * @param  string $key
     * @param  mixed  $value
     * @return mixed
     */
    protected function applyAccessor(string $key, $value)
    {
        if (isset($this->accessors[$key])) {
            return call_user_func($this->accessors[$key], $value);
        }

        // Aplicar casting automático
        return $this->castToPhpType($key, $value);
    }

    /**
     * Valida si una cadena es un UUID válido.
     *
     * @param  string $uuid
     * @return bool
     */
    private function isValidUuid(string $uuid): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuid) === 1;
    }

    /**
     * Limpia la caché de tipos de propiedades.
     * Útil durante testing o cuando se modifican tipos dinámicamente.
     *
     * @return void
     */
    public static function clearPropertyTypesCache(): void
    {
        self::$cachedPropertyTypes = null;
    }

    /**
     * Limpia la caché del esquema de base de datos.
     *
     * @return void
     */
    public function clearDatabaseSchemaCache(): void
    {
        $this->databaseSchemaCache = null;
    }
}
