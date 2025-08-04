<?php

declare(strict_types=1);

namespace VersaORM;

/**
 * VersaModel - Modelo base ActiveRecord para VersaORM.
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

    /**
     * Campos que pueden ser asignados masivamente.
     * Si está vacío, se usa $guarded para determinar campos protegidos.
     * @var array<string>
     */
    protected array $fillable = [];

    /**
     * Campos protegidos contra asignación masiva.
     * Por defecto protege todos los campos ('*').
     * @var array<string>
     */
    protected array $guarded = ['*'];

    /**
     * Reglas de validación personalizadas del modelo.
     * Pueden ser sobrescritas por modelos específicos.
     * @var array<string, array<string>>
     */
    protected array $rules = [];

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
     * Obtiene la instancia global del ORM.
     *
     * @return VersaORM|null
     */
    public static function getGlobalORM(): ?VersaORM
    {
        return self::$ormInstance;
    }

    /**
     * Obtiene la instancia del ORM para uso en traits.
     *
     * @return VersaORM|array<string, mixed>|null
     */
    protected function getOrm()
    {
        return $this->orm;
    }

    /**
     * Rellena el modelo con un array de atributos respetando Mass Assignment.
     *
     * @param array<string, mixed> $attributes
     * @return self
     * @throws VersaORMException
     */
    public function fill(array $attributes): self
    {
        $fillableAttributes = $this->filterFillableAttributes($attributes);

        foreach ($fillableAttributes as $key => $value) {
            $this->attributes[$key] = $value;
        }

        return $this;
    }

    /**
     * Filtra atributos basándose en las reglas de Mass Assignment.
     *
     * @param array<string, mixed> $attributes
     * @return array<string, mixed>
     * @throws VersaORMException
     */
    protected function filterFillableAttributes(array $attributes): array
    {
        // Si $fillable está definido y no está vacío, usar solo esos campos
        if (!empty($this->fillable)) {
            $filtered = [];
            foreach ($attributes as $key => $value) {
                if (in_array($key, $this->fillable, true)) {
                    $filtered[$key] = $value;
                } else {
                    throw new VersaORMException(
                        "Field '{$key}' is not fillable. Add it to the \$fillable array in your model or remove it from mass assignment.",
                        'MASS_ASSIGNMENT_ERROR',
                        null,
                        [],
                        ['field' => $key, 'fillable' => $this->fillable]
                    );
                }
            }
            return $filtered;
        }

        // Si $fillable está vacío, usar $guarded para excluir campos
        if (in_array('*', $this->guarded, true)) {
            // Si guarded contiene '*', todos los campos están protegidos por defecto
            throw new VersaORMException(
                "Mass assignment is not allowed. Define \$fillable fields in your model or remove '*' from \$guarded.",
                'MASS_ASSIGNMENT_BLOCKED',
                null,
                [],
                ['guarded' => $this->guarded, 'attempted_fields' => array_keys($attributes)]
            );
        }

        // Filtrar campos que no están en $guarded
        $filtered = [];
        foreach ($attributes as $key => $value) {
            if (!in_array($key, $this->guarded, true)) {
                $filtered[$key] = $value;
            } else {
                throw new VersaORMException(
                    "Field '{$key}' is guarded against mass assignment.",
                    'GUARDED_FIELD_ERROR',
                    null,
                    [],
                    ['field' => $key, 'guarded' => $this->guarded]
                );
            }
        }

        return $filtered;
    }

    /**
     * Valida los datos del modelo según las reglas definidas y el esquema de la base de datos.
     *
     * @return array<string> Array de errores de validación (vacío si es válido)
     * @throws VersaORMException
     */
    public function validate(): array
    {
        $errors = [];

        // Validaciones automáticas desde esquema (se implementará con metadata del CLI Rust)
        $schemaValidationErrors = $this->validateAgainstSchema();
        $errors = array_merge($errors, $schemaValidationErrors);

        // Validaciones personalizadas del modelo
        $customValidationErrors = $this->validateCustomRules();
        $errors = array_merge($errors, $customValidationErrors);

        return $errors;
    }

    /**
     * Valida contra el esquema de la base de datos (usando metadatos del CLI Rust).
     *
     * @return array<string>
     */
    protected function validateAgainstSchema(): array
    {
        $errors = [];

        try {
            // Obtener el esquema de validación desde Rust
            $validationSchema = $this->getTableValidationSchema();

            if (empty($validationSchema)) {
                // Si no podemos obtener el esquema, usar validaciones básicas
                return $this->basicSchemaValidation();
            }

            // Validar cada campo del modelo contra el esquema
            foreach ($this->attributes as $field => $value) {
                if (!isset($validationSchema[$field])) {
                    continue; // Campo no existe en el esquema
                }

                $columnSchema = $validationSchema[$field];
                $fieldErrors = $this->validateFieldAgainstSchema($field, $value, $columnSchema);
                $errors = array_merge($errors, $fieldErrors);
            }

            // Validar campos requeridos que no están presentes
            foreach ($validationSchema as $fieldName => $columnSchema) {
                if (
                    ($columnSchema['is_required'] ?? false) &&
                    !isset($this->attributes[$fieldName]) &&
                    !($columnSchema['is_auto_increment'] ?? false)
                ) {
                    $errors[] = "The {$fieldName} field is required.";
                }
            }
        } catch (VersaORMException $e) {
            // En caso de error al obtener el esquema, usar validación básica
            return $this->basicSchemaValidation();
        }

        return $errors;
    }

    /**
     * Obtiene el esquema de validación desde Rust.
     *
     * @return array<string, array<string, mixed>>
     * @throws VersaORMException
     */
    protected function getTableValidationSchema(): array
    {
        $orm = $this->orm ?? self::$ormInstance;
        if (!($orm instanceof VersaORM)) {
            throw new VersaORMException('No ORM instance available for schema validation');
        }

        try {
            // Llamar al esquema del CLI de Rust para obtener metadatos de la tabla
            $result = $orm->schema('columns', $this->table);

            if (is_array($result) && !empty($result)) {
                return $this->processSchemaToValidationRules($result);
            }
        } catch (\Exception $e) {
            // Si hay error al obtener el esquema, usar validación básica en silencio
            // Esto permite que la aplicación funcione incluso si el CLI Rust no está disponible
            return [];
        }

        return [];
    }

    /**
     * Procesa el esquema de columnas de Rust y lo convierte a reglas de validación.
     *
     * @param array<array<string, mixed>> $schemaColumns
     * @return array<string, array<string, mixed>>
     */
    protected function processSchemaToValidationRules(array $schemaColumns): array
    {
        $validationSchema = [];

        foreach ($schemaColumns as $column) {
            if (!isset($column['column_name'])) {
                continue;
            }

            $columnName = $column['column_name'];
            $dataType = strtolower($column['data_type'] ?? '');
            $isNullable = ($column['is_nullable'] ?? 'YES') === 'YES';
            $maxLength = $column['character_maximum_length'] ?? null;
            $isAutoIncrement = ($column['extra'] ?? '') === 'auto_increment';
            $isRequired = !$isNullable && ($column['column_default'] === null) && !$isAutoIncrement;

            $validationRules = [];

            // Reglas basadas en el tipo de datos
            if (strpos($dataType, 'varchar') !== false || strpos($dataType, 'char') !== false) {
                if ($maxLength) {
                    $validationRules[] = "max:{$maxLength}";
                }
            }

            if (strpos($dataType, 'int') !== false) {
                $validationRules[] = 'numeric';
            }

            if (strpos($dataType, 'decimal') !== false || strpos($dataType, 'float') !== false || strpos($dataType, 'double') !== false) {
                $validationRules[] = 'numeric';
            }

            // Agregar validación de email para campos que contienen 'email' en el nombre
            if (strpos($columnName, 'email') !== false) {
                $validationRules[] = 'email';
            }

            // Si es requerido, agregar la regla required
            if ($isRequired) {
                $validationRules[] = 'required';
            }

            $validationSchema[$columnName] = [
                'is_required' => $isRequired,
                'is_nullable' => $isNullable,
                'is_auto_increment' => $isAutoIncrement,
                'max_length' => $maxLength,
                'data_type' => $dataType,
                'validation_rules' => $validationRules,
            ];
        }

        return $validationSchema;
    }

    /**
     * Valida un campo específico contra su esquema de columna.
     *
     * @param string $field
     * @param mixed $value
     * @param array<string, mixed> $columnSchema
     * @return array<string>
     */
    protected function validateFieldAgainstSchema(string $field, $value, array $columnSchema): array
    {
        $errors = [];

        // Validar si el campo es requerido
        if (($columnSchema['is_required'] ?? false) && ($value === null || $value === '')) {
            $errors[] = "The {$field} field is required.";
            return $errors; // No validar más si está vacío y es requerido
        }

        // Si el valor es null y la columna lo permite, no validar más
        if ($value === null && ($columnSchema['is_nullable'] ?? false)) {
            return $errors;
        }

        // Validar longitud máxima
        if (($columnSchema['max_length'] ?? 0) && is_string($value)) {
            if (strlen($value) > $columnSchema['max_length']) {
                $errors[] = "The {$field} may not be greater than {$columnSchema['max_length']} characters.";
            }
        }

        // Validar tipo de datos
        $dataType = strtolower($columnSchema['data_type'] ?? '');
        if (strpos($dataType, 'int') !== false) {
            if (!is_numeric($value) || (string) (int) $value !== (string) $value) {
                $errors[] = "The {$field} must be an integer.";
            }
        } elseif (strpos($dataType, 'decimal') !== false || strpos($dataType, 'float') !== false) {
            if (!is_numeric($value)) {
                $errors[] = "The {$field} must be a number.";
            }
        }

        // Aplicar reglas de validación automáticas derivadas del esquema
        if (!empty($columnSchema['validation_rules'])) {
            foreach ($columnSchema['validation_rules'] as $rule) {
                $error = $this->validateSingleRule($field, $value, $rule);
                if ($error !== null) {
                    $errors[] = $error;
                }
            }
        }

        return $errors;
    }

    /**
     * Validación básica cuando no se puede obtener el esquema.
     *
     * @return array<string>
     */
    protected function basicSchemaValidation(): array
    {
        $errors = [];

        foreach ($this->attributes as $field => $value) {
            // Validación básica de campos vacío vs NULL
            if ($value === '' || $value === null) {
                // Campos comunes que suelen ser auto-increment o tienen valores por defecto
                if (!in_array($field, ['id', 'created_at', 'updated_at'])) {
                    // Esta es una validación muy básica
                    // En un proyecto real, esto se configuraría por modelo
                }
            }
        }

        return $errors;
    }

    /**
     * Valida usando reglas personalizadas definidas en el modelo.
     *
     * @return array<string>
     */
    protected function validateCustomRules(): array
    {
        $errors = [];

        foreach ($this->rules as $field => $rules) {
            if (!isset($this->attributes[$field])) {
                continue;
            }

            $value = $this->attributes[$field];

            foreach ($rules as $rule) {
                $error = $this->validateSingleRule($field, $value, $rule);
                if ($error !== null) {
                    $errors[] = $error;
                }
            }
        }

        return $errors;
    }

    /**
     * Valida una sola regla contra un campo.
     *
     * @param string $field
     * @param mixed $value
     * @param string $rule
     * @return string|null
     */
    protected function validateSingleRule(string $field, $value, string $rule): ?string
    {
        switch ($rule) {
            case 'required':
                if (empty($value)) {
                    return "The {$field} field is required.";
                }
                break;

            case 'email':
                if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    return "The {$field} must be a valid email address.";
                }
                break;

            case 'numeric':
                if (!is_numeric($value)) {
                    return "The {$field} must be numeric.";
                }
                break;

            default:
                // Reglas con parámetros (ej: 'max:255', 'min:3')
                if (strpos($rule, ':') !== false) {
                    [$ruleName, $parameter] = explode(':', $rule, 2);

                    switch ($ruleName) {
                        case 'max':
                            if (is_string($value) && strlen($value) > (int) $parameter) {
                                return "The {$field} may not be greater than {$parameter} characters.";
                            }
                            break;

                        case 'min':
                            if (is_string($value) && strlen($value) < (int) $parameter) {
                                return "The {$field} must be at least {$parameter} characters.";
                            }
                            break;
                    }
                }
                break;
        }

        return null;
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
            // Separar los datos normales de las relaciones
            $relations = [];
            $attributes = [];

            foreach ($data as $key => $value) {
                // Si la clave corresponde a una relación (es un array u objeto)
                if (method_exists($this, $key) && (is_array($value) || is_object($value))) {
                    $relations[$key] = $value;
                } else {
                    $attributes[$key] = $value;
                }
            }

            $this->attributes = $attributes;

            // Cargar las relaciones encontradas
            foreach ($relations as $relationName => $relationData) {
                // Convertir los datos de la relación en instancias de modelo apropiadas
                if (method_exists($this, $relationName)) {
                    $relationInstance = $this->{$relationName}();

                    if (
                        $relationInstance instanceof \VersaORM\Relations\HasMany ||
                        $relationInstance instanceof \VersaORM\Relations\BelongsToMany
                    ) {
                        // Para relaciones "many", convertir cada elemento del array en un modelo
                        $modelInstances = [];
                        if (is_array($relationData)) {
                            $relatedModelClass = get_class($relationInstance->query->getModelInstance());
                            $relatedTable = $relationInstance->query->getTable();

                            foreach ($relationData as $relatedRecord) {
                                if (is_array($relatedRecord)) {
                                    $relatedModel = new $relatedModelClass($relatedTable, $this->orm);
                                    $relatedModel->loadInstance($relatedRecord);
                                    $modelInstances[] = $relatedModel;
                                }
                            }
                        }
                        $this->relations[$relationName] = $modelInstances;
                    } else {
                        // Para relaciones "one", convertir el único registro en un modelo
                        if (is_array($relationData)) {
                            $relatedModelClass = get_class($relationInstance->query->getModelInstance());
                            $relatedTable = $relationInstance->query->getTable();

                            $relatedModel = new $relatedModelClass($relatedTable, $this->orm);
                            $relatedModel->loadInstance($relationData);
                            $this->relations[$relationName] = $relatedModel;
                        } else {
                            $this->relations[$relationName] = $relationData;
                        }
                    }
                } else {
                    // Si no hay método de relación, almacenar como está
                    $this->relations[$relationName] = $relationData;
                }
            }

            return $this;
        }

        // Si es un ID, buscar en la base de datos
        $orm = $this->orm ?? self::$ormInstance;
        if (!($orm instanceof VersaORM)) {
            throw new \Exception('No ORM instance available for load operation');
        }

        $result = $orm->exec("SELECT * FROM {$this->table} WHERE {$pk} = ?", [$data]);
        if (is_array($result) && !empty($result) && is_array($result[0])) {
            $this->attributes = $result[0];
        } else {
            throw new \Exception('Record not found or invalid result format');
        }

        return $this;
    }


    /**
     * Guardar el modelo en la base de datos.
     * Ejecuta validación antes de guardar.
     *
     * @return void
     * @throws VersaORMException
     */
    public function store(): void
    {
        // Ejecutar validación antes de guardar
        $validationErrors = $this->validate();
        if (!empty($validationErrors)) {
            throw new VersaORMException(
                'Validation failed: ' . implode(', ', $validationErrors),
                'VALIDATION_ERROR',
                null,
                [],
                ['errors' => $validationErrors, 'attributes' => $this->attributes]
            );
        }

        $orm = $this->orm ?? self::$ormInstance;
        if (!($orm instanceof VersaORM)) {
            throw new VersaORMException(
                'No ORM instance available for store operation',
                'NO_ORM_INSTANCE'
            );
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

            $sql = "UPDATE {$this->table} SET " . implode(', ', $fields) . ' WHERE id = ?';
            $orm->exec($sql, $params);
        } else {
            // INSERT nuevo - filtrar campos que no deben insertarse manualmente
            $filteredAttributes = $this->attributes;
            unset($filteredAttributes['id']); // No insertar ID manualmente
            unset($filteredAttributes['created_at']); // Dejar que MySQL lo maneje
            unset($filteredAttributes['updated_at']); // Dejar que MySQL lo maneje

            if (empty($filteredAttributes)) {
                throw new VersaORMException(
                    'No data to insert',
                    'NO_DATA_TO_INSERT'
                );
            }

            $fields = array_keys($filteredAttributes);
            $placeholders = array_fill(0, count($fields), '?');

            $sql = "INSERT INTO {$this->table} (" . implode(', ', $fields) . ') VALUES (' . implode(', ', $placeholders) . ')';
            $orm->exec($sql, array_values($filteredAttributes));

            // Obtener el ID del registro recién insertado
            // Como LAST_INSERT_ID() no funciona como esperado, buscaremos el registro más reciente
            // que coincida con los datos que acabamos de insertar
            $whereConditions = [];
            $whereParams = [];

            // Usar campos únicos para encontrar el registro
            if (isset($filteredAttributes['email'])) {
                $whereConditions[] = 'email = ?';
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
            throw new \Exception('Cannot delete without an ID');
        }

        $orm = $this->orm ?? self::$ormInstance;
        if (!($orm instanceof VersaORM)) {
            throw new \Exception('No ORM instance available for trash operation');
        }

        $sql = "DELETE FROM {$this->table} WHERE id = ?";
        $orm->exec($sql, [$this->attributes['id']]);

        // Limpiar los atributos ya que el registro fue eliminado
        $this->attributes = [];
    }

    /**
     * Asignar valor a un atributo.
     * Nota: Para mass assignment seguro, usar fill() en su lugar.
     *
     * @param string $key
     * @param mixed $value
     */
    public function __set(string $key, $value): void
    {
        $this->attributes[$key] = $value;
    }

    /**
     * Crear una nueva instancia del modelo y rellenarla con atributos seguros.
     *
     * @param array<string, mixed> $attributes
     * @return static
     */
    public static function create(array $attributes): static
    {
        /** @var static $instance */
        $instance = new static('', self::$ormInstance);
        assert($instance instanceof static);
        $instance->fill($attributes);
        return $instance;
    }

    /**
     * Actualizar el modelo con nuevos atributos respetando Mass Assignment.
     *
     * @param array<string, mixed> $attributes
     * @return self
     * @throws VersaORMException
     */
    public function update(array $attributes): self
    {
        $this->fill($attributes);
        $this->store();
        return $this;
    }

    /**
     * Obtener todos los atributos que pueden ser rellenados masivamente.
     *
     * @return array<string>
     */
    public function getFillable(): array
    {
        return $this->fillable;
    }

    /**
     * Obtener todos los atributos protegidos contra mass assignment.
     *
     * @return array<string>
     */
    public function getGuarded(): array
    {
        return $this->guarded;
    }

    /**
     * Determinar si un atributo puede ser rellenado masivamente.
     *
     * @param string $key
     * @return bool
     */
    public function isFillable(string $key): bool
    {
        // Si fillable tiene valores, solo esos campos son permitidos
        if (!empty($this->fillable)) {
            return in_array($key, $this->fillable, true);
        }

        // Si fillable está vacío, verificar que no esté en guarded
        if (in_array('*', $this->guarded, true)) {
            return false; // Todos están protegidos
        }

        return !in_array($key, $this->guarded, true);
    }

    /**
     * Determinar si un atributo está protegido contra mass assignment.
     *
     * @param string $key
     * @return bool
     */
    public function isGuarded(string $key): bool
    {
        return !$this->isFillable($key);
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
            throw new \Exception('No ORM instance available. Call Model::setORM() first.');
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
            throw new \Exception('No ORM instance available. Call Model::setORM() first.');
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
            throw new \Exception('No ORM instance available. Call VersaModel::setORM() first.');
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
            throw new \Exception('No ORM instance available. Call VersaModel::setORM() first.');
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
            throw new \Exception('No ORM instance available. Call VersaModel::setORM() first.');
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
            throw new \Exception('No ORM instance available. Call VersaModel::setORM() first.');
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
            throw new \Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }
        $result = self::$ormInstance->table($table, static::class)->where($pk, '=', $id)->findOne();
        // Si el resultado es instancia de modelo pero no tiene atributos, intentar cargar los datos manualmente
        if ($result instanceof self && (empty($result->getData()) || !isset($result->getData()['id']))) {
            $data = self::$ormInstance->exec("SELECT * FROM {$table} WHERE {$pk} = ?", [$id]);
            if (is_array($data) && !empty($data) && is_array($data[0])) {
                $result->loadInstance($data[0]);
            }
        }
        return $result;
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
            throw new \Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }

        $queryBuilder = self::$ormInstance->table($table, static::class);

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
