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
     * @var array<string, array<string, mixed>>
     */
    // Cache por clase para evitar colisiones entre distintos modelos
    private static array $cachedPropertyTypes = [];

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
        'int'        => 'integer',
        'integer'    => 'integer',
        'real'       => 'float',
        'float'      => 'float',
        'double'     => 'float',
        'decimal'    => 'float',
        'string'     => 'string',
        'bool'       => 'boolean',
        'boolean'    => 'boolean',
        'object'     => 'object',
        'array'      => 'array',
        'collection' => 'array',
        'date'       => 'datetime',
        'datetime'   => 'datetime',
        'timestamp'  => 'datetime',
        'json'       => 'json',
        'uuid'       => 'uuid',
        'enum'       => 'enum',
        'set'        => 'set',
        'blob'       => 'blob',
        'inet'       => 'inet',
    ];

    /**
     * Mapa de handlers de casting PHP (inicializado bajo demanda).
     * @var array<string, callable>
     */
    private static array $phpCastHandlers = [];

    /**
     * Mapa de handlers de casting a DB (inicializado bajo demanda).
     * @var array<string, callable>
     */
    private static array $dbCastHandlers = [];

    /**
     * Inicializa (si es necesario) y devuelve los handlers de casting a PHP.
     * Cada handler firma: function(self $self, string $property, mixed $value, array $typeDefinition): mixed
     * @return array<string, callable>
     */
    private static function getPhpCastHandlers(): array
    {
        if (self::$phpCastHandlers) {
            return self::$phpCastHandlers;
        }

        // Handlers reutilizados por sinónimos
        $intHandler = static function ($self, string $property, $value) {
            return is_numeric($value) ? (int) $value : 0;
        };

        $floatHandler = static function ($self, string $property, $value) {
            return is_numeric($value) ? (float) $value : 0.0;
        };

        $stringHandler = static function ($self, string $property, $value) {
            return is_scalar($value) ? (string) $value : '';
        };

        $boolHandler = static function ($self, string $property, $value) {
            if (is_string($value)) {
                return in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
            }
            return (bool) $value;
        };

        $arrayHandler = static function ($self, string $property, $value) {
            if (is_string($value)) {
                $decoded = json_decode($value, true);
                return $decoded !== null ? $decoded : [];
            }
            return is_array($value) ? $value : [$value];
        };

        $jsonHandler = static function ($self, string $property, $value, array $typeDefinition = []) {
            if (is_string($value)) {
                $decoded = json_decode($value, true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new VersaORMException("Invalid JSON for property {$property}: " . json_last_error_msg());
                }
                return $decoded;
            }
            return $value;
        };

        $uuidHandler = static function ($self, string $property, $value) {
            $uuidValue = (string) $value;
            if (!$self->isValidUuid($uuidValue)) {
                if ($property === 'uuid') {
                    throw new VersaORMException("Invalid UUID format for property {$property}: {$uuidValue}");
                }
                throw new \InvalidArgumentException('Invalid UUID format');
            }
            return $uuidValue;
        };

        $datetimeHandler = static function ($self, string $property, $value) {
            if (is_string($value)) {
                return new \DateTime($value);
            }
            if ($value instanceof \DateTime) {
                return $value;
            }
            return new \DateTime('@' . (int) $value);
        };

        $enumHandler = static function ($self, string $property, $value, array $typeDefinition) {
            $enumValue     = (string) $value;
            $allowedValues = $typeDefinition['values'] ?? [];
            if (!empty($allowedValues) && !in_array($enumValue, $allowedValues, true)) {
                throw new VersaORMException("Invalid enum value for property {$property}. Allowed: " . implode(', ', $allowedValues));
            }
            return $enumValue;
        };

        $setHandler = static function ($self, string $property, $value, array $typeDefinition) {
            if (is_string($value)) {
                $decoded = json_decode($value, true);
                if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                    $setValue = $decoded;
                } else {
                    $setValue = $value === '' ? [] : explode(',', $value);
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
        };

        $blobHandler = static function ($self, string $property, $value) {
            return $value; // sin transformación
        };

        $inetHandler = static function ($self, string $property, $value) {
            $inetValue = (string) $value;
            if (!filter_var($inetValue, FILTER_VALIDATE_IP)) {
                throw new VersaORMException("Invalid IP address for property {$property}: {$inetValue}");
            }
            return $inetValue;
        };

        // Registrar sinónimos apuntando al mismo handler
        $map = [
            'int'        => $intHandler,
            'integer'    => $intHandler,
            'float'      => $floatHandler,
            'real'       => $floatHandler,
            'double'     => $floatHandler,
            'decimal'    => $floatHandler,
            'string'     => $stringHandler,
            'bool'       => $boolHandler,
            'boolean'    => $boolHandler,
            'array'      => $arrayHandler,
            'collection' => $arrayHandler,
            'json'       => $jsonHandler,
            'uuid'       => $uuidHandler,
            'datetime'   => $datetimeHandler,
            'date'       => $datetimeHandler,
            'timestamp'  => $datetimeHandler,
            'enum'       => $enumHandler,
            'set'        => $setHandler,
            'blob'       => $blobHandler,
            'inet'       => $inetHandler,
        ];

        self::$phpCastHandlers = $map;
        return self::$phpCastHandlers;
    }

    /**
     * Inicializa (si es necesario) y devuelve los handlers de casting a DB.
     * Cada handler firma: function(self $self, string $property, mixed $value, array $typeDefinition): mixed
     * @return array<string, callable>
     */
    private static function getDbCastHandlers(): array
    {
        if (self::$dbCastHandlers) {
            return self::$dbCastHandlers;
        }

        $intHandler = static function ($self, string $property, $value) {
            return (int) $value;
        };

        $floatHandler = static function ($self, string $property, $value) {
            return (float) $value;
        };

        $stringHandler = static function ($self, string $property, $value, array $typeDefinition) {
            $stringValue = (string) $value;
            $maxLength   = $typeDefinition['max_length'] ?? null;
            if ($maxLength && strlen($stringValue) > $maxLength) {
                throw new VersaORMException("String too long for property {$property}. Max: {$maxLength}, got: " . strlen($stringValue));
            }
            return $stringValue;
        };

        /** @var callable(object,string,mixed):int */
        $boolHandler = static function ($self, string $property, mixed $value): int {
            return (bool) $value ? 1 : 0;
        };

        /** @var callable(object,string,mixed):string */
        $jsonLikeHandler = static function ($self, string $property, mixed $value): string {
            return json_encode($value, JSON_UNESCAPED_UNICODE) ?: 'null';
        };

        /** @var callable(object,string,mixed):string */
        $uuidHandler = static function ($self, string $property, mixed $value): string {
            $uuidValue = (string)$value;
            if (!$self->isValidUuid($uuidValue)) {
                throw new VersaORMException("Invalid UUID format for property {$property}: {$uuidValue}");
            }
            return $uuidValue;
        };

        /** @var callable(object,string,mixed):string */
        $datetimeHandler = static function ($self, string $property, mixed $value): string {
            if ($value instanceof \DateTimeInterface) {
                return $value->format('Y-m-d H:i:s');
            }
            if (is_string($value)) {
                return (new \DateTime($value))->format('Y-m-d H:i:s');
            }
            return date('Y-m-d H:i:s', is_numeric($value) ? (int)$value : time());
        };

        /** @var callable(object,string,mixed,array<string,mixed>):string */
        $enumHandler = static function ($self, string $property, mixed $value, array $typeDefinition): string {
            $enumValue = (string)$value;
            /** @var array<int|string,mixed> $allowedValues */
            $allowedValues = is_array($typeDefinition['values'] ?? null) ? $typeDefinition['values'] : [];
            if ($allowedValues !== [] && !in_array($enumValue, $allowedValues, true)) {
                throw new VersaORMException("Invalid enum value for property {$property}. Allowed: " . implode(', ', array_map('strval', $allowedValues)));
            }
            return $enumValue;
        };

        /** @var callable(object,string,mixed,array<string,mixed>):string */
        $setHandler = static function ($self, string $property, mixed $value, array $typeDefinition): string {
            $setValue = is_array($value) ? $value : [$value];
            /** @var array<int|string,mixed> $allowedValues */
            $allowedValues = is_array($typeDefinition['values'] ?? null) ? $typeDefinition['values'] : [];
            if ($allowedValues !== []) {
                foreach ($setValue as $val) {
                    if (!in_array($val, $allowedValues, true)) {
                        throw new VersaORMException("Invalid set value '{$val}' for property {$property}. Allowed: " . implode(', ', array_map('strval', $allowedValues)));
                    }
                }
            }
            return implode(',', array_map('strval', $setValue));
        };

        /** @var callable(object,string,mixed):mixed */
        $blobHandler = static function ($self, string $property, mixed $value): mixed {
            return $value; // sin transformación
        };

        /** @var callable(object,string,mixed):string */
        $inetHandler = static function ($self, string $property, mixed $value): string {
            $inetValue = (string)$value;
            if (!filter_var($inetValue, FILTER_VALIDATE_IP)) {
                throw new VersaORMException("Invalid IP address for property {$property}: {$inetValue}");
            }
            return $inetValue;
        };

        $map = [
            'int'        => $intHandler,
            'integer'    => $intHandler,
            'float'      => $floatHandler,
            'real'       => $floatHandler,
            'double'     => $floatHandler,
            'decimal'    => $floatHandler,
            'string'     => $stringHandler,
            'bool'       => $boolHandler,
            'boolean'    => $boolHandler,
            'array'      => $jsonLikeHandler,
            'collection' => $jsonLikeHandler,
            'json'       => $jsonLikeHandler,
            'uuid'       => $uuidHandler,
            'datetime'   => $datetimeHandler,
            'date'       => $datetimeHandler,
            'timestamp'  => $datetimeHandler,
            'enum'       => $enumHandler,
            'set'        => $setHandler,
            'blob'       => $blobHandler,
            'inet'       => $inetHandler,
        ];

        self::$dbCastHandlers = $map;
        return self::$dbCastHandlers;
    }

    /**
     * Obtiene los tipos de propiedades definidos para el modelo.
     * Los modelos concretos normalmente sobreescriben este método.
     * Aquí devolvemos (y cacheamos) un array vacío por defecto para cumplir la interfaz.
     *
     * @return array<string, array<string,mixed>>
     */
    public static function getPropertyTypes(): array
    {
        $called = static::class;
        if (isset(self::$cachedPropertyTypes[$called])) {
            return self::$cachedPropertyTypes[$called];
        }

        $types = [];
        // Permitimos que el modelo defina un método protegido/privado static definePropertyTypes()
        if (method_exists($called, 'definePropertyTypes')) {
            try {
                $refMethod = new \ReflectionMethod($called, 'definePropertyTypes');
                if (!$refMethod->isPublic()) {
                    $refMethod->setAccessible(true);
                }
                // Invocar método estático sin instancia
                $result = $refMethod->invoke(null);
                if (is_array($result)) {
                    $types = $result;
                }
            } catch (\Throwable $e) {
                // Silencioso: en caso de fallo, devolvemos array vacío y dejamos que tests detecten
                $types = [];
            }
        }

        // Normalización simple: asegurar 'type' en minúsculas si existe
        foreach ($types as $prop => &$def) {
            if (isset($def['type']) && is_string($def['type'])) {
                $def['type'] = strtolower($def['type']);
            }
        }
        unset($def);

        return self::$cachedPropertyTypes[$called] = $types;
    }

    /**
     * Convierte un valor crudo de la base de datos al tipo PHP apropiado.
     * Implementación basada en un mapa de handlers para evitar grandes switch.
     *
     * @param string $property
     * @param mixed $value
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
            // Heurística ligera: intentar decodificar JSON y detectar DateTime
            if (is_string($value)) {
                $trim = trim($value);
                if ($trim !== '' && ($trim[0] === '{' || $trim[0] === '[')) {
                    $decoded = json_decode($value, true);
                    if (json_last_error() === JSON_ERROR_NONE) {
                        return $decoded;
                    }
                }
                try {
                    if (preg_match('/^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?/', $trim) === 1) {
                        return new \DateTime($trim);
                    }
                } catch (\Throwable $e) {
                    // ignorar y retornar valor original
                }
            }
            return $value; // Sin conversión si no hay tipo definido
        }

        $typeDefinition = $propertyTypes[$property];
        $type           = $typeDefinition['type'] ?? 'string';

        $handlers = self::getPhpCastHandlers();
        /** @var callable(object,string,mixed,array<string,mixed>):mixed $handler */
        $handler = $handlers[$type] ?? static function ($self, string $property, mixed $value): mixed {
            return $value; // fallback
        };

        try {
            return $handler($this, $property, $value, $typeDefinition);
        } catch (\Exception $e) {
            if ($e instanceof VersaORMException || $e instanceof \InvalidArgumentException) {
                throw $e;
            }
            throw new VersaORMException(
                "Error casting property {$property} to PHP type {$type}: " . $e->getMessage(),
                'TYPE_CASTING_ERROR'
            );
        }
    }

    /**
     * Convierte un valor PHP al formato apropiado para la base de datos.
     *
     * @param string $property
     * @param mixed $value
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
            // Heurística: convertir arrays/objetos a JSON, DateTime a string, bool a 0/1
            if ($value instanceof \DateTime) {
                return $value->format('Y-m-d H:i:s');
            }
            if (is_array($value) || is_object($value)) {
                return json_encode($value, JSON_UNESCAPED_UNICODE);
            }
            if (is_bool($value)) {
                return $value ? 1 : 0;
            }
            return $value; // Sin conversión si no hay tipo definido
        }

        $typeDefinition = $propertyTypes[$property];
        $type           = $typeDefinition['type'] ?? 'string';

        $handlers = self::getDbCastHandlers();
        /** @var callable(object,string,mixed):mixed $handler */
        $handler = $handlers[$type] ?? static function ($self, string $property, mixed $value): mixed {
            return $value; // fallback
        };

        try {
            return $handler($this, $property, $value);
        } catch (\Exception $e) {
            if ($e instanceof VersaORMException || $e instanceof \InvalidArgumentException) {
                throw $e;
            }
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
        $errors        = [];
        $propertyTypes = static::getPropertyTypes();

        if (empty($propertyTypes)) {
            return ['No property types defined for model ' . static::class];
        }

        try {
            // Validar que tenemos una instancia de VersaORM
            if (!($this->orm instanceof \VersaORM\VersaORM)) {
                $errors[] = 'Se requiere una instancia válida de VersaORM para validar el esquema';
                return $errors;
            }

            // Obtener esquema real de la base de datos (soporta fallback PDO schema action)
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
                    $warning  = "⚠️  ADVERTENCIA: La propiedad '{$property}' no existe en la base de datos";
                    $errors[] = $warning;
                    if (php_sapi_name() === 'cli') {
                        echo "\033[33m{$warning}\033[0m\n";
                    }
                    continue;
                }

                $dbColumn  = $dbColumns[$columnName];
                $dbType    = strtolower($dbColumn['data_type']);
                $modelType = strtolower($definition['type']);

                // Mapear tipos de base de datos a tipos del modelo
                $typeMapping = [
                    'varchar'   => 'string',
                    'char'      => 'string',
                    'text'      => 'string',
                    'longtext'  => 'text',
                    'int'       => 'int',
                    'integer'   => 'int',
                    'bigint'    => 'int',
                    'smallint'  => 'int',
                    'tinyint'   => 'boolean',
                    'decimal'   => 'decimal',
                    'numeric'   => 'decimal',
                    'float'     => 'float',
                    'double'    => 'float',
                    'real'      => 'float',
                    'date'      => 'date',
                    'datetime'  => 'datetime',
                    'timestamp' => 'datetime',
                    'time'      => 'time',
                    'json'      => 'json',
                    'jsonb'     => 'json',
                    'blob'      => 'blob',
                    'longblob'  => 'blob',
                    'binary'    => 'binary',
                    'varbinary' => 'binary',
                    'enum'      => 'enum',
                    'set'       => 'set',
                    'uuid'      => 'uuid',
                    'inet'      => 'inet',
                ];

                $expectedType = $typeMapping[$dbType] ?? $dbType;

                if ($expectedType !== $modelType && !$this->isCompatibleType($expectedType, $modelType)) {
                    $warning  = "⚠️  INCONSISTENCIA: '{$property}' - DB: {$dbType} ({$expectedType}) vs Modelo: {$modelType}";
                    $errors[] = $warning;
                    if (php_sapi_name() === 'cli') {
                        echo "\033[31m{$warning}\033[0m\n";
                    }
                }

                // Verificar nullabilidad
                $isNullable    = strtolower($dbColumn['is_nullable'] ?? 'no') === 'yes';
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
                    $warning  = "💡 INFO: Columna '{$columnName}' existe en DB pero no está definida en el modelo";
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
            'string'    => ['text', 'varchar', 'char'],
            'text'      => ['string', 'varchar', 'char'],
            'int'       => ['integer', 'bigint', 'smallint'],
            'integer'   => ['int', 'bigint', 'smallint'],
            'float'     => ['double', 'real', 'decimal'],
            'decimal'   => ['float', 'double', 'numeric'],
            'boolean'   => ['tinyint', 'bit'],
            'datetime'  => ['timestamp', 'date'],
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
            $schema                    = $this->getTableValidationSchema();
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
     * @param string $key
     * @param mixed $value
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
     * @param string $key
     * @param mixed $value
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
     * @param string $uuid
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
        $calledClass = static::class;
        if (isset(self::$cachedPropertyTypes[$calledClass])) {
            unset(self::$cachedPropertyTypes[$calledClass]);
        }
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

    /**
     * Valida consistencia de una propiedad vs definición de columna DB.
     * Usado por tests SchemaConsistencyTest vía reflexión.
     *
     * @param string $property
     * @param array<string,mixed> $propertyDef
     * @param array<string,mixed> $dbColumn
     * @return array<int,string>
     */
    private function validatePropertyConsistency(string $property, array $propertyDef, array $dbColumn): array
    {
        $errors    = [];
        $modelType = strtolower((string)($propertyDef['type'] ?? ''));
        $dbType    = strtolower((string)($dbColumn['data_type'] ?? ''));

        // Mapeo y compatibilidad ampliada
        $compatMap = [
            'int'      => ['int', 'integer', 'tinyint', 'smallint', 'bigint'],
            'float'    => ['float', 'double', 'real', 'decimal', 'numeric'],
            'string'   => ['varchar', 'char', 'text', 'mediumtext', 'longtext'],
            'bool'     => ['tinyint', 'boolean', 'bit'],
            'boolean'  => ['tinyint', 'boolean', 'bit'],
            'datetime' => ['datetime', 'timestamp', 'date'],
            'date'     => ['date', 'datetime', 'timestamp'],
            'json'     => ['json', 'jsonb', 'text'],
            'uuid'     => ['uuid', 'char', 'varchar'],
            'enum'     => ['enum'],
            'set'      => ['set'],
            'blob'     => ['blob', 'longblob', 'mediumblob', 'tinyblob'],
            'inet'     => ['inet', 'varchar', 'char'],
        ];

        $isTypeOk = in_array($dbType, $compatMap[$modelType] ?? [], true) || $dbType === $modelType;
        if (!$isTypeOk) {
            $errors[] = "Type mismatch for property '{$property}': model={$modelType} db={$dbType}";
        }

        // Nullability
        if (isset($propertyDef['nullable'])) {
            $modelNullable = (bool)$propertyDef['nullable'];
            $dbNullable    = strtoupper((string)($dbColumn['is_nullable'] ?? 'NO')) === 'YES';
            if ($modelNullable !== $dbNullable) {
                $errors[] = "Nullability mismatch for property '{$property}': model=" . ($modelNullable ? 'YES' : 'NO') . ' db=' . ($dbNullable ? 'YES' : 'NO');
            }
        }

        // Longitud
        if (isset($propertyDef['max_length']) && ($propertyDef['max_length'] ?? null) !== null) {
            $modelLen = (int)$propertyDef['max_length'];
            $dbLen    = (int)($dbColumn['character_maximum_length'] ?? 0);
            if ($dbLen > 0 && $modelLen > $dbLen) {
                $errors[] = "Length mismatch for property '{$property}': model={$modelLen} db={$dbLen}";
            }
        }

        return $errors;
    }
}
