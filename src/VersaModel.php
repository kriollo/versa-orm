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
 * @version 1.0.0
 *
 * @author  VersaORM Team
 * @license MIT
 */

use DateTime;
use DateTimeInterface;
use Exception;
use ReflectionClass;
use Throwable;
use VersaORM\Interfaces\TypedModelInterface;
use VersaORM\Relations\BelongsToMany;
use VersaORM\Relations\HasMany;
use VersaORM\Traits\HasRelationships;
use VersaORM\Traits\HasStrongTyping;

use function assert;
use function count;
use function in_array;
use function is_array;
use function is_bool;
use function is_float;
use function is_int;
use function is_object;
use function is_string;
use function strlen;

class VersaModel implements TypedModelInterface
{
    use HasRelationships;
    use HasStrongTyping {
        HasStrongTyping::getPropertyTypes as private traitGetPropertyTypes;
        HasStrongTyping::castToPhpType as private traitCastToPhpType;
    }

    // Métodos y traits ya definidos arriba

    /**
     * Listeners de eventos por modelo.
     *
     * @var array<string, array<int, callable>>
     */
    protected static array $eventListeners = [];

    protected string $table;

    /**
     * Campos que pueden ser asignados masivamente.
     * Si está vacío, se usa $guarded para determinar campos protegidos.
     *
     * @var array<string>
     */
    protected array $fillable = [];

    /**
     * Campos protegidos contra asignación masiva.
     * Por defecto protege todos los campos ('*').
     *
     * @var array<string>
     */
    protected array $guarded = ['*'];

    /**
     * Reglas de validación personalizadas del modelo.
     * Pueden ser sobrescritas por modelos específicos.
     *
     * @var array<string, array<string>>
     */
    protected array $rules = [];

    /**
     * @var array<string, mixed>|VersaORM|null
     */
    private $orm; // Puede ser array (config) o instancia de VersaORM

    /**
     * Atributos dinámicos del modelo cargados desde la base de datos o asignados.
     *
     * @var array<string, mixed>
     */
    private array $attributes = [];

    private static ?VersaORM $ormInstance = null;

    /**
     * @param array<string, mixed>|VersaORM|null $orm
     */
    public function __construct(string $table, $orm)
    {
        $this->table = $table;
        $this->orm = $orm;
    }

    /**
     * Asignar valor a un atributo con casting automático.
     * Nota: Para mass assignment seguro, usar fill() en su lugar.
     */
    public function __set(string $key, mixed $value): void
    {
        // Aplicar mutadores y casting si el trait HasStrongTyping está disponible
        if (method_exists($this, 'applyMutator')) {
            $value = $this->applyMutator($key, $value);
        }

        $this->attributes[$key] = $value;
    }

    /**
     * Obtener el valor de un atributo con casting automático.
     *
     * @return mixed
     */
    public function __get(string $key)
    {
        // Atajos para $this->orm y $this->db
        if ($key === 'orm' || $key === 'db') {
            return self::orm();
        }

        if (isset($this->attributes[$key])) {
            $value = $this->attributes[$key];

            // Aplicar accesorios y casting si el trait HasStrongTyping está disponible
            if (method_exists($this, 'applyAccessor')) {
                return $this->applyAccessor($key, $value);
            }

            return $value;
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
     * Verificar si existe un atributo.
     */
    public function __isset(string $key): bool
    {
        return isset($this->attributes[$key]);
    }

    /**
     * Eliminar un atributo.
     */
    public function __unset(string $key): void
    {
        unset($this->attributes[$key]);
    }

    /**
     * Devuelve el nombre de la tabla asociada al modelo.
     * Si la subclase define una propiedad estática $table, la usa; si no, infiere por convención.
     */
    public static function tableName(): string
    {
        $cls = static::class;
        $vars = get_class_vars($cls);
        if (isset($vars['table']) && is_string($vars['table']) && $vars['table'] !== '') {
            return $vars['table'];
        }
        $class = (new \ReflectionClass($cls))->getShortName();
        $table = strtolower($class);
        if (str_ends_with($table, 'y')) {
            $table = substr($table, 0, -1) . 'ies';
        } else {
            $table .= 's';
        }

        return $table;
    }

    /**
     * Limpia todos los listeners de eventos registrados (para testing).
     */
    public static function clearEventListeners(): void
    {
        static::$eventListeners = [];
    }

    /**
     * Registrar un listener para un evento del ciclo de vida.
     *
     * @param string $event Nombre del evento (creating, created, updating, etc.)
     * @param callable $listener Callback que recibe ($model, ModelEvent $event)
     */
    public static function on(string $event, callable $listener): void
    {
        static::$eventListeners[$event][] = $listener;
    }

    /**
     * Wrapper explícito para garantizar que el cargador vea la implementación.
     *
     * @return array<string,array<string,mixed>>
     */
    public static function getPropertyTypes(): array
    {
        // Usar late static binding para que static::class dentro del trait
        // refleje correctamente la subclase (p.ej. TestTypedModel) y pueda
        // descubrir su método protected static definePropertyTypes().
        return static::traitGetPropertyTypes();
    }

    /**
     * Wrapper explícito para el método de casting a PHP.
     *
     * @param mixed $value
     *
     * @return mixed
     */
    public function castToPhpType(string $property, $value)
    {
        return $this->traitCastToPhpType($property, $value);
    }

    /* =============================================================
     * Accesos simplificados solicitados: $this->orm / $this->db y
     * self::orm() / self::db() para evitar repetir getGlobalORM().
     * ============================================================= */
    /** Obtiene instancia global o lanza excepción clara. */
    public static function orm(): VersaORM
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new VersaORMException('No global ORM instance set. Call VersaModel::setORM() first.');
        }

        return self::$ormInstance;
    }

    /** Alias semántico (db). */
    public static function db(): VersaORM
    {
        return self::orm();
    }

    /**
     * Configura la instancia global del ORM para métodos estáticos.
     */
    public static function setORM(?VersaORM $orm): void
    {
        self::$ormInstance = $orm;
    }

    /**
     * Obtiene la instancia global del ORM.
     */
    public static function getGlobalORM(): ?VersaORM
    {
        return self::$ormInstance;
    }

    /**
     * Congela o descongela este modelo específico.
     * Esto bloquea operaciones DDL en el esquema relacionado con este modelo.
     *
     * @throws VersaORMException
     */
    public static function freeze(bool $frozen = true): void
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new VersaORMException(
                'No global ORM instance set. Call VersaModel::setORM() first.',
                'NO_ORM_INSTANCE',
            );
        }

        $modelClass = static::class;
        self::$ormInstance->freezeModel($modelClass, $frozen);
    }

    /**
     * Verifica si este modelo está congelado.
     *
     * @throws VersaORMException
     */
    public static function isFrozen(): bool
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new VersaORMException(
                'No global ORM instance set. Call VersaModel::setORM() first.',
                'NO_ORM_INSTANCE',
            );
        }

        $modelClass = static::class;

        return self::$ormInstance->isModelFrozen($modelClass);
    }

    /**
     * Rellena el modelo con un array de atributos respetando Mass Assignment.
     *
     * @param array<string, mixed> $attributes
     *
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
     * Valida los datos del modelo según las reglas definidas y el esquema de la base de datos.
     *
     * @throws VersaORMException
     *
     * @return array<string> Array de errores de validación (vacío si es válido)
     */
    public function validate(): array
    {
        $errors = [];

        // Validaciones automáticas desde esquema (se implementará con metadata del CLI Rust)
        $schemaValidationErrors = $this->validateAgainstSchema();
        $errors = array_merge($errors, $schemaValidationErrors);

        // Validaciones personalizadas del modelo
        $customValidationErrors = $this->validateCustomRules();

        return array_merge($errors, $customValidationErrors);
    }

    /**
     * Carga la configuración de mapeo de tipos desde el archivo JSON.
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed>
     */
    public static function loadTypeMappingConfig(string $configPath): array
    {
        if (! file_exists($configPath)) {
            throw new VersaORMException("Type mapping configuration file not found: {$configPath}");
        }

        $content = file_get_contents($configPath);

        if ($content === false) {
            throw new VersaORMException("Could not read type mapping configuration file: {$configPath}");
        }

        $config = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new VersaORMException('Invalid JSON in type mapping configuration: ' . json_last_error_msg());
        }

        return $config;
    }

    /**
     * Convierte un valor según el mapping avanzado definido en el archivo JSON.
     *
     * @param array<string, mixed> $fieldSchema
     *
     * @throws VersaORMException
     *
     * @return mixed
     */
    public function convertValueByTypeMapping(string $field, mixed $value, array $fieldSchema)
    {
        $type = $fieldSchema['type'] ?? null;

        if (! $type) {
            throw new VersaORMException("Type mapping not defined for field: {$field}");
        }

        switch ($type) {
            case 'json':
                if (is_string($value)) {
                    return json_decode($value, true);
                }

                return $value;
            case 'uuid':
                return (string) $value; // Assuming validation has ensured UUID format
            case 'array':
                if (is_string($value)) {
                    $decoded = json_decode($value, true);

                    return $decoded ?? [$value];
                }

                return is_array($value) ? $value : [$value];
            case 'set':
            case 'enum':
                if (is_string($value)) {
                    // For SET and ENUM, we might have comma-separated values
                    return explode(',', $value);
                }

                return is_array($value) ? $value : [$value];
            default:
                return $value;
        }
    }

    /**
     * Cargar los datos del modelo desde la base de datos (método de instancia).
     *
     * @param array<string, mixed>|int|string $data Puede ser un ID para buscar o un array de datos para cargar directamente
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

            // Aplicar casting de tipos a los atributos antes de asignarlos
            $castedAttributes = [];

            foreach ($attributes as $key => $value) {
                try {
                    // Usar castToPhpType directamente para asignar atributos internos
                    $castedAttributes[$key] = $this->castToPhpType($key, $value);
                } catch (Throwable) {
                    // Fallback al valor original si el casting falla
                    $castedAttributes[$key] = $value;
                }
            }
            $this->attributes = $castedAttributes;

            // Cargar las relaciones encontradas
            foreach ($relations as $relationName => $relationData) {
                // Convertir los datos de la relación en instancias de modelo apropiadas
                if (method_exists($this, $relationName)) {
                    $relationInstance = $this->{$relationName}();

                    if (
                        $relationInstance instanceof HasMany
                        || $relationInstance instanceof BelongsToMany
                    ) {
                        // Para relaciones "many", convertir cada elemento del array en un modelo
                        $modelInstances = [];

                        if (is_array($relationData)) {
                            $relatedModelClass = $relationInstance->query->getModelInstance()::class;
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
                    } elseif (is_array($relationData)) {
                        // Para relaciones "one", convertir el único registro en un modelo
                        $relatedModelClass = $relationInstance->query->getModelInstance()::class;
                        $relatedTable = $relationInstance->query->getTable();
                        $relatedModel = new $relatedModelClass($relatedTable, $this->orm);
                        $relatedModel->loadInstance($relationData);
                        $this->relations[$relationName] = $relatedModel;
                    } else {
                        $this->relations[$relationName] = $relationData;
                    }
                } else {
                    // Si no hay método de relación, almacenar como está
                    $this->relations[$relationName] = $relationData;
                }
            }

            // Evento: retrieved
            $this->fireEvent('retrieved');

            return $this;
        }

        // Si es un ID, buscar en la base de datos
        $orm = $this->orm ?? self::$ormInstance;

        if (! $orm instanceof VersaORM) {
            throw new Exception('No ORM instance available for load operation');
        }

        $result = $orm->exec("SELECT * FROM {$this->table} WHERE {$pk} = ?", [$data]);

        if (is_array($result) && $result !== [] && is_array($result[0])) {
            // Usar loadInstance para aplicar casting correctamente
            $this->loadInstance($result[0]);
        } else {
            throw new Exception('Record not found or invalid result format');
        }

        return $this;
    }

    /**
     * Guardar el modelo en la base de datos.
     * Ejecuta validación antes de guardar.
     * Si el modo freeze está desactivado, creará automáticamente columnas faltantes.
     * Devuelve el ID (existente o insertado) si puede determinarse.
     *
     * @throws VersaORMException
     */
    public function store(): int|string|null
    {
        // Ejecutar validación antes de guardar
        $validationErrors = $this->validate();
        if ($validationErrors !== []) {
            throw new VersaORMException(
                'Validation failed: ' . implode(', ', $validationErrors),
                'VALIDATION_ERROR',
                null,
                [],
                ['errors' => $validationErrors, 'attributes' => $this->attributes],
            );
        }

        // Evento: saving (antes de cualquier operación)
        if (! $this->fireEvent('saving')) {
            return null;
        }

        $orm = $this->orm ?? self::$ormInstance;
        if (! $orm instanceof VersaORM) {
            throw new VersaORMException(
                'No ORM instance available for store operation',
                'NO_ORM_INSTANCE',
            );
        }

        // Intentar asegurar que tabla/columnas existan si freeze está desactivado
        try {
            $this->ensureColumnsExist($orm);
        } catch (VersaORMException $e) {
            // Si la tabla no existe, crearla mínimamente y reintentar ensureColumnsExist
            if (stripos($e->getMessage(), 'no such table') !== false || stripos($e->getMessage(), 'doesn\'t exist') !== false) {
                $this->createBaseTableIfMissing($orm);
                $this->ensureColumnsExist($orm);
            }
        }

        if (isset($this->attributes['id'])) {
            // UPDATE existente
            if (! $this->fireEvent('updating')) {
                return null;
            }
            $fields = [];
            $params = [];
            foreach ($this->attributes as $key => $value) {
                if ($key !== 'id') {
                    $fields[] = "{$key} = ?";
                    $params[] = $this->prepareValueForDatabase($key, $value);
                }
            }
            $params[] = $this->attributes['id'];
            if ($fields !== []) { // Sólo ejecutar si hay algo que actualizar
                $sql = "UPDATE {$this->table} SET " . implode(', ', $fields) . ' WHERE id = ?';
                $orm->exec($sql, $params);
            }
            $this->fireEvent('updated');
            $this->fireEvent('saved');

            return $this->attributes['id'];
        }

        // INSERT nuevo - filtrar campos que no deben insertarse manualmente
        if (! $this->fireEvent('creating')) {
            return null;
        }
        $filteredAttributes = $this->attributes;
        unset($filteredAttributes['id']); // No insertar ID manualmente
        // Preparar valores para la base de datos (convertir DateTime a string, etc.)
        $preparedAttributes = [];
        foreach ($filteredAttributes as $key => $value) {
            $preparedAttributes[$key] = $this->prepareValueForDatabase($key, $value);
        }
        if ($preparedAttributes === []) {
            throw new VersaORMException(
                'No data to insert',
                'NO_DATA_TO_INSERT',
            );
        }

        // Intentar obtener el ID en forma nativa usando el QueryBuilder
        try {
            /** @var int|string|null $newId */
            $newId = $orm->table($this->table)->insertGetId($preparedAttributes);
            if ($newId !== null && $newId !== '') {
                // Normalizar a int si es numérico
                $this->attributes['id'] = is_numeric($newId) ? (int) $newId : $newId;
                $this->fireEvent('created');
                $this->fireEvent('saved');

                return $this->attributes['id']; // Insert completado con ID asignado
            }
        } catch (Throwable) {
            // Continuar con fallback silencioso
        }
        // Fallback: buscar el registro más reciente que coincida con los datos insertados
        $whereConditions = [];
        $whereParams = [];
        // Usar campos únicos comunes para encontrar el registro
        if (isset($preparedAttributes['email'])) {
            $whereConditions[] = 'email = ?';
            $whereParams[] = $preparedAttributes['email'];
        } else {
            // Si no hay un campo único obvio, usar el primer campo escalar
            foreach ($preparedAttributes as $key => $value) {
                if (is_string($value) || is_numeric($value)) {
                    $whereConditions[] = "{$key} = ?";
                    $whereParams[] = $value;
                    break; // Solo usar el primer campo válido
                }
            }
        }
        if ($whereConditions !== []) {
            $whereClause = implode(' AND ', $whereConditions);
            $fallbackResult = $orm->exec("SELECT * FROM {$this->table} WHERE {$whereClause} ORDER BY id DESC LIMIT 1", $whereParams);
            if (is_array($fallbackResult) && $fallbackResult !== [] && is_array($fallbackResult[0])) {
                // Merge los datos y luego aplicar casting
                $mergedData = array_merge($this->attributes, $fallbackResult[0]);
                $this->loadInstance($mergedData);
                $this->fireEvent('created');
                $this->fireEvent('saved');

                return $this->attributes['id'] ?? null;
            }
        }
        $this->fireEvent('saved');

        return $this->attributes['id'] ?? null;
    }

    /**
     * Guarda el modelo y devuelve el ID insertado (si aplica). En updates devuelve el ID existente.
     * No lanza excepción adicional más allá de las de store().
     */
    public function storeAndGetId(): int|string|null
    {
        return $this->store();
    }

    /**
     * Upsert (insertar o actualizar) el modelo usando claves únicas.
     *
     * @param array<int, string> $uniqueKeys Columnas que determinan duplicados
     * @param array<int, string> $updateColumns Columnas a actualizar en caso de duplicado (opcional)
     *
     * @throws VersaORMException Si los datos son inválidos
     *
     * @return array<string, mixed> Información sobre la operación realizada
     */
    public function upsert(array $uniqueKeys, array $updateColumns = []): array
    {
        if ($this->attributes === []) {
            throw new VersaORMException(
                'upsert requires model data',
                'NO_DATA_FOR_UPSERT',
            );
        }

        if ($uniqueKeys === []) {
            throw new VersaORMException(
                'upsert requires unique keys to detect duplicates',
                'NO_UNIQUE_KEYS',
            );
        }

        // Ejecutar validación antes de upsert
        $validationErrors = $this->validate();

        if ($validationErrors !== []) {
            throw new VersaORMException(
                'Validation failed: ' . implode(', ', $validationErrors),
                'VALIDATION_ERROR',
                null,
                [],
                ['errors' => $validationErrors, 'attributes' => $this->attributes],
            );
        }

        $orm = $this->orm ?? self::$ormInstance;

        if (! $orm instanceof VersaORM) {
            throw new VersaORMException(
                'No ORM instance available for upsert operation',
                'NO_ORM_INSTANCE',
            );
        }

        // Verificar y crear columnas faltantes si freeze está desactivado
        $this->ensureColumnsExist($orm);

        // Usar el QueryBuilder para hacer upsert
        $result = $orm->table($this->table)
            ->upsert($this->attributes, $uniqueKeys, $updateColumns);

        // Si fue exitoso y se insertó un nuevo registro, actualizar el ID si es posible
        if (isset($result['operation']) && $result['operation'] === 'inserted_or_updated') {
            // Intentar obtener el ID del registro después del upsert
            $whereConditions = [];

            foreach ($uniqueKeys as $key) {
                if (isset($this->attributes[$key])) {
                    $whereConditions[$key] = $this->attributes[$key];
                }
            }

            if ($whereConditions !== []) {
                $query = $orm->table($this->table);

                foreach ($whereConditions as $key => $value) {
                    $query->where($key, '=', $value);
                }
                $updated = $query->firstArray();

                if ($updated && isset($updated['id'])) {
                    $this->attributes['id'] = $updated['id'];
                }
            }
        }

        return $result;
    }

    /**
     * Método save() inteligente - Detecta automáticamente si insertar o actualizar.
     * Utiliza la clave primaria para determinar la operación.
     *
     * @param string $primaryKey Nombre de la clave primaria (default: 'id')
     *
     * @throws VersaORMException Si los datos son inválidos
     *
     * @return array<string, mixed> Información sobre la operación realizada
     */
    public function save(string $primaryKey = 'id'): array
    {
        if ($this->attributes === []) {
            throw new VersaORMException(
                'save requires model data',
                'NO_DATA_FOR_SAVE',
            );
        }

        // Ejecutar validación antes de guardar
        $validationErrors = $this->validate();

        if ($validationErrors !== []) {
            throw new VersaORMException(
                'Validation failed: ' . implode(', ', $validationErrors),
                'VALIDATION_ERROR',
                null,
                [],
                ['errors' => $validationErrors, 'attributes' => $this->attributes],
            );
        }

        $orm = $this->orm ?? self::$ormInstance;

        if (! $orm instanceof VersaORM) {
            throw new VersaORMException(
                'No ORM instance available for save operation',
                'NO_ORM_INSTANCE',
            );
        }

        // Verificar y crear columnas faltantes si freeze está desactivado
        $this->ensureColumnsExist($orm);

        // Usar el QueryBuilder para hacer save inteligente
        $result = $orm->table($this->table)
            ->save($this->attributes, $primaryKey);

        // Actualizar el modelo con los datos devueltos
        if (isset($result['id'])) {
            $this->attributes[$primaryKey] = $result['id'];
        }

        return $result;
    }

    /**
     * Método insertOrUpdate() - Verifica existencia y decide operación.
     *
     * @param array<int, string> $uniqueKeys Columnas para verificar existencia
     * @param array<int, string> $updateColumns Columnas a actualizar (opcional)
     *
     * @throws VersaORMException Si los datos son inválidos
     *
     * @return array<string, mixed> Información sobre la operación realizada
     */
    public function insertOrUpdate(array $uniqueKeys, array $updateColumns = []): array
    {
        if ($this->attributes === []) {
            throw new VersaORMException(
                'insertOrUpdate requires model data',
                'NO_DATA_FOR_INSERT_OR_UPDATE',
            );
        }

        if ($uniqueKeys === []) {
            throw new VersaORMException(
                'insertOrUpdate requires unique keys to check existence',
                'NO_UNIQUE_KEYS',
            );
        }

        // Ejecutar validación antes de la operación
        $validationErrors = $this->validate();

        if ($validationErrors !== []) {
            throw new VersaORMException(
                'Validation failed: ' . implode(', ', $validationErrors),
                'VALIDATION_ERROR',
                null,
                [],
                ['errors' => $validationErrors, 'attributes' => $this->attributes],
            );
        }

        $orm = $this->orm ?? self::$ormInstance;

        if (! $orm instanceof VersaORM) {
            throw new VersaORMException(
                'No ORM instance available for insertOrUpdate operation',
                'NO_ORM_INSTANCE',
            );
        }

        // Verificar y crear columnas faltantes si freeze está desactivado
        $this->ensureColumnsExist($orm);

        // Usar el QueryBuilder para hacer insertOrUpdate
        return $orm->table($this->table)
            ->insertOrUpdate($this->attributes, $uniqueKeys, $updateColumns);
    }

    /**
     * Método createOrUpdate() con condiciones personalizadas.
     *
     * @param array<string, mixed> $conditions Condiciones personalizadas para verificar existencia
     * @param array<int, string> $updateColumns Columnas a actualizar (opcional)
     *
     * @throws VersaORMException Si los datos son inválidos
     *
     * @return array<string, mixed> Información sobre la operación realizada
     */
    public function createOrUpdate(array $conditions, array $updateColumns = []): array
    {
        if ($this->attributes === []) {
            throw new VersaORMException(
                'createOrUpdate requires model data',
                'NO_DATA_FOR_CREATE_OR_UPDATE',
            );
        }

        if ($conditions === []) {
            throw new VersaORMException(
                'createOrUpdate requires conditions to check existence',
                'NO_CONDITIONS',
            );
        }

        // Ejecutar validación antes de la operación
        $validationErrors = $this->validate();

        if ($validationErrors !== []) {
            throw new VersaORMException(
                'Validation failed: ' . implode(', ', $validationErrors),
                'VALIDATION_ERROR',
                null,
                [],
                ['errors' => $validationErrors, 'attributes' => $this->attributes],
            );
        }

        $orm = $this->orm ?? self::$ormInstance;

        if (! $orm instanceof VersaORM) {
            throw new VersaORMException(
                'No ORM instance available for createOrUpdate operation',
                'NO_ORM_INSTANCE',
            );
        }

        // Verificar y crear columnas faltantes si freeze está desactivado
        $this->ensureColumnsExist($orm);

        // Usar el QueryBuilder para hacer createOrUpdate
        $result = $orm->table($this->table)
            ->createOrUpdate($this->attributes, $conditions, $updateColumns);

        // Actualizar el modelo con el ID si se creó un nuevo registro
        if (isset($result['id'])) {
            $this->attributes['id'] = $result['id'];
        }

        return $result;
    }

    /**
     * Auto-detectar claves únicas desde el esquema de la tabla.
     *
     * @throws VersaORMException Si no se puede obtener información del esquema
     *
     * @return array<string> Lista de columnas que forman claves únicas
     */
    public function getUniqueKeys(): array
    {
        $orm = $this->orm ?? self::$ormInstance;

        if (! $orm instanceof VersaORM) {
            throw new VersaORMException(
                'No ORM instance available for schema inspection',
                'NO_ORM_INSTANCE',
            );
        }

        try {
            // Usar el método público schema para obtener información de índices únicos
            $result = $orm->schema('unique_keys', $this->table);

            if (is_array($result) && isset($result['unique_keys'])) {
                return $result['unique_keys'];
            }

            // Fallback: buscar columnas comunes que suelen ser únicas
            $commonUniqueColumns = ['email', 'username', 'slug', 'code', 'sku'];
            $detectedKeys = [];

            foreach ($commonUniqueColumns as $column) {
                if (isset($this->attributes[$column])) {
                    $detectedKeys[] = $column;
                }
            }

            return $detectedKeys;
        } catch (Exception) {
            // Si falla, devolver claves comunes como fallback
            return ['id'];
        }
    }

    /**
     * Upsert inteligente - Auto-detecta claves únicas y realiza upsert.
     *
     * @param array<int, string>|null $updateColumns Columnas a actualizar (opcional)
     *
     * @throws VersaORMException Si no se pueden detectar claves únicas
     *
     * @return array<string, mixed> Información sobre la operación realizada
     */
    public function smartUpsert(?array $updateColumns = null): array
    {
        $uniqueKeys = $this->getUniqueKeys();

        if ($uniqueKeys === []) {
            throw new VersaORMException(
                'Cannot perform smart upsert: no unique keys detected in table schema',
                'NO_UNIQUE_KEYS_DETECTED',
            );
        }

        return $this->upsert($uniqueKeys, $updateColumns ?? []);
    }

    /**
     * Eliminar el registro del modelo en la base de datos.
     */
    public function trash(): void
    {
        if (! isset($this->attributes['id'])) {
            throw new Exception('Cannot delete without an ID');
        }

        // Evento: deleting (antes de eliminar)
        if (! $this->fireEvent('deleting')) {
            return;
        }

        $orm = $this->orm ?? self::$ormInstance;
        if (! $orm instanceof VersaORM) {
            throw new Exception('No ORM instance available for trash operation');
        }

        $sql = "DELETE FROM {$this->table} WHERE id = ?";
        $orm->exec($sql, [$this->attributes['id']]);

        // Evento: deleted (después de eliminar)
        $this->fireEvent('deleted');

        // Limpiar los atributos ya que el registro fue eliminado
        $this->attributes = [];
    }

    /**
     * Crear una nueva instancia del modelo y rellenarla con atributos seguros.
     *
     * @param array<string, mixed> $attributes
     */
    public static function create(array $attributes): static
    {
        /**
         * @var static $instance
         */
        $instance = new static('', self::$ormInstance);
        assert($instance instanceof static);
        $instance->fill($attributes);

        return $instance;
    }

    /**
     * Actualizar el modelo con nuevos atributos respetando Mass Assignment.
     *
     * @param array<string, mixed> $attributes
     *
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
     */
    public function isFillable(string $key): bool
    {
        // Si fillable tiene valores, solo esos campos son permitidos
        if ($this->fillable !== []) {
            return in_array($key, $this->fillable, true);
        }

        // Si fillable está vacío, verificar que no esté en guarded
        if (in_array('*', $this->guarded, true)) {
            return false; // Todos están protegidos
        }

        return ! in_array($key, $this->guarded, true);
    }

    /**
     * Determinar si un atributo está protegido contra mass assignment.
     */
    public function isGuarded(string $key): bool
    {
        return ! $this->isFillable($key);
    }

    /**
     * Obtiene el valor de un atributo del modelo (valor crudo).
     *
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
        // Usar el método seguro que acabamos de crear
        return $this->getDataCasted();
    }

    /**
     * Exportar una colección de modelos a un array de arrays.
     *
     * @param array<self> $models Array de instancias de Model
     *
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

    public function getForeignKey(): string
    {
        return strtolower(basename(str_replace('\\', '/', static::class))) . '_id';
    }

    public function getKeyName(): string
    {
        return 'id';
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
            throw new Exception('ORM configuration not found.');
        }

        return (new VersaORM($config))->table($this->table, static::class);
    }

    /**
     * Obtiene el nombre de la tabla.
     */
    public function getTable(): string
    {
        return $this->table;
    }

    /**
     * Atajo fluido para construir un QueryBuilder asociado a ESTE modelo (mantiene modelClass para casting).
     * Ejemplo: $this->query()->where('activo', true)->getAll();
     * Permite también sobrescribir tabla opcionalmente: $this->query('otra_tabla')->getAll();.
     */
    public function query(?string $table = null): QueryBuilder
    {
        $orm = $this->orm instanceof VersaORM ? $this->orm : self::orm();

        return $orm->table($table ?? $this->table, static::class);
    }

    /**
     * Devuelve el nombre de la tabla asociada al modelo.
     * Si la subclase define una propiedad estática $tableName, la usa; si no, infiere por convención.
     */
    /**
     * Variante estática para conveniencia cuando no se tiene instancia: UserModel::queryTable()->where(...).
     */
    public static function queryTable(?string $table = null): QueryBuilder
    {
        return self::orm()->table($table ?? static::tableName(), static::class);
    }

    /**
     * Obtiene todos los datos del modelo (atributos crudos).
     *
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return $this->attributes;
    }

    /**
     * Obtiene todos los datos del modelo con casting de tipos aplicado.
     *
     * @return array<string, mixed>
     */
    public function getDataCasted(): array
    {
        $data = [];
        $types = static::getPropertyTypes();

        foreach ($this->attributes as $key => $value) {
            try {
                // Aplicar casting manual más directo para casos problemáticos
                if (isset($types[$key], $types[$key]['type'])) {
                    $type = $types[$key]['type'];

                    // Casting directo para tipos comunes
                    switch ($type) {
                        case 'boolean':
                        case 'bool':
                            $data[$key] = $value === null ? null : (bool) $value;
                            break;
                        case 'integer':
                        case 'int':
                            $data[$key] = $value === null ? null : (int) $value;
                            break;
                        case 'float':
                        case 'double':
                        case 'real':
                            $data[$key] = $value === null ? null : (float) $value;
                            break;
                        case 'string':
                            $data[$key] = $value === null ? null : (string) $value;
                            break;
                        case 'datetime':
                        case 'date':
                            if ($value === null) {
                                $data[$key] = null;
                            } elseif ($value instanceof DateTime) {
                                $data[$key] = $value; // Ya es DateTime
                            } else {
                                try {
                                    $data[$key] = new DateTime((string) $value);
                                } catch (Throwable) {
                                    $data[$key] = $value; // Fallback
                                }
                            }
                            break;
                        default:
                            // Para otros tipos, usar el casting del trait
                            $data[$key] = $this->applyAccessor($key, $value);
                    }
                } else {
                    // Si no hay tipo definido, usar applyAccessor
                    $data[$key] = $this->applyAccessor($key, $value);
                }
            } catch (Throwable) {
                // Fallback al valor original si el casting falla
                $data[$key] = $value;
            }
        }

        return $data;
    }

    /**
     * Crea un nuevo modelo vacío (método estático).
     */
    public static function dispense(string $table): self
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new Exception('No ORM instance available. Call Model::setORM() first.');
        }

        return new self($table, self::$ormInstance);
    }

    /**
     * Cargar un modelo por ID (método estático).
     *
     * @param int|string $id
     */
    public static function load(string $table, $id, string $pk = 'id'): ?self
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new Exception('No ORM instance available. Call Model::setORM() first.');
        }

        try {
            $data = self::$ormInstance->exec("SELECT * FROM {$table} WHERE {$pk} = ?", [$id]);

            if (! is_array($data) || $data === [] || ! is_array($data[0])) {
                return null;
            }

            $model = new static($table, self::$ormInstance);
            // Usar loadInstance para aplicar casting correctamente
            $model->loadInstance($data[0]);

            return $model;
        } catch (Exception) {
            return null;
        }
    }

    /**
     * Crea una nueva instancia del modelo y la asocia a la ORM actual.
     *
     * Crea una nueva instancia del modelo para la tabla dada.
     */
    public function dispenseInstance(string $table): self
    {
        return new self($table, $this->orm);
    }

    // ========== MÉTODOS GENERALES DE CONSULTA ==========

    /**
     * Cuenta registros en una tabla con condiciones opcionales.
     *
     * @param array<int, mixed> $bindings
     */
    public static function count(string $table, ?string $conditions = null, array $bindings = []): int
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }
        $sql = "SELECT COUNT(*) as count FROM {$table}";

        if ($conditions !== null && $conditions !== '' && $conditions !== '0') {
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
     * @param array<int, mixed> $bindings
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getAll(string $sql, array $bindings = []): array
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }
        $result = self::$ormInstance->exec($sql, $bindings);

        if (is_array($result)) {
            $rows = array_filter($result, 'is_array');

            // Aplicar casting de tipos si la clase define property types
            try {
                if (method_exists(static::class, 'getPropertyTypes')) {
                    /** @var array<string,array<string,mixed>> $types */
                    $types = static::getPropertyTypes();

                    if ($types !== []) {
                        $tmp = new static('', self::$ormInstance);

                        foreach ($rows as $index => $row) {
                            foreach ($row as $k => $v) {
                                if (isset($types[$k])) {
                                    try {
                                        $rows[$index][$k] = $tmp->castToPhpType($k, $v);
                                    } catch (Throwable) {
                                        // fallback silencioso al valor original
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (Throwable) {
                // Si algo falla, devolver sin casting
            }

            return $rows;
        }

        return [];
    }

    /**
     * Obtiene una sola fila como array.
     *
     * @param array<int, mixed> $bindings
     *
     * @return array<string, mixed>|null
     */
    public static function getRow(string $sql, array $bindings = []): ?array
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }
        $result = self::$ormInstance->exec($sql, $bindings);

        if (is_array($result) && isset($result[0]) && is_array($result[0])) {
            $row = $result[0];

            // Intentar aplicar casting fuerte si la clase define property types
            try {
                if (method_exists(static::class, 'getPropertyTypes')) {
                    /** @var array<string,array<string,mixed>> $types */
                    $types = static::getPropertyTypes();

                    if ($types !== []) {
                        $tmp = new static($row['_table'] ?? '', self::$ormInstance);

                        foreach ($row as $k => $v) {
                            if (isset($types[$k])) {
                                try {
                                    $row[$k] = $tmp->castToPhpType($k, $v);
                                } catch (Throwable) {
                                    // fallback silencioso
                                }
                            }
                        }
                    }
                }
            } catch (Throwable) {
            }

            return $row;
        }

        return null;
    }

    /**
     * Obtiene un solo valor de una consulta.
     *
     * @param array<int, mixed> $bindings
     *
     * @return mixed
     */
    public static function getCell(string $sql, array $bindings = [])
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }
        $result = self::$ormInstance->exec($sql, $bindings);

        if (is_array($result) && $result !== [] && is_array($result[0])) {
            $row = $result[0];
            $value = array_values($row)[0] ?? null;

            // Intentar caster el primer valor si tenemos tipos
            try {
                if (method_exists(static::class, 'getPropertyTypes')) {
                    $types = static::getPropertyTypes();
                    // Encontrar la primera clave asociada al valor
                    $firstKey = array_key_first($row);

                    if ($firstKey !== null && isset($types[$firstKey])) {
                        $tmp = new static($row['_table'] ?? '', self::$ormInstance);

                        try {
                            $value = $tmp->castToPhpType($firstKey, $value);
                        } catch (Throwable) {
                        }
                    }
                }
            } catch (Throwable) {
            }

            return $value;
        }

        return null;
    }

    // ========== MÉTODOS ACTIVERECORD ESTÁTICOS ==========
    /**
     * Busca un registro por ID y lo devuelve como modelo.
     */
    public static function findOne(string $table, mixed $id, string $pk = 'id'): ?self
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }

        // Si $id es un arreglo asociativo se interpreta como condiciones columna=>valor
        if (is_array($id)) {
            $qb = self::$ormInstance->table($table, static::class);

            foreach ($id as $col => $val) {
                // Solo columnas no vacías
                if (is_string($col) && $col !== '') {
                    $qb->where($col, '=', $val);
                }
            }

            $result = $qb->findOne();
        } else {
            $result = self::$ormInstance->table($table, static::class)->where($pk, '=', $id)->findOne();
        }

        // Si el resultado es instancia de modelo pero no tiene atributos, intentar cargar los datos manualmente
        if ($result instanceof self && ($result->getData() === [] || ! isset($result->getData()['id']))) {
            // Si $id es array, construir WHERE con la primera condición encontrada
            if (is_array($id) && $id !== []) {
                $firstKey = array_key_first($id);
                $firstVal = $id[$firstKey];

                $data = self::$ormInstance->exec("SELECT * FROM {$table} WHERE {$firstKey} = ?", [$firstVal]);
            } else {
                $data = self::$ormInstance->exec("SELECT * FROM {$table} WHERE {$pk} = ?", [$id]);
            }

            if (is_array($data) && $data !== [] && is_array($data[0])) {
                $result->loadInstance($data[0]);
            }
        }

        return $result;
    }

    /**
     * Busca registros con condiciones y los devuelve como array de modelos.
     *
     * @param array<int, mixed> $bindings
     *
     * @return array<int, self>
     */
    public static function findAll(string $table, ?string $conditions = null, array $bindings = []): array
    {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }

        $queryBuilder = self::$ormInstance->table($table, static::class);

        if ($conditions !== null && $conditions !== '' && $conditions !== '0') {
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
     * Procesa registros en lotes para manejar grandes conjuntos de datos.
     *
     * @param string $table nombre de la tabla
     * @param callable $callback función a ejecutar por cada lote de modelos
     * @param int $batchSize tamaño de cada lote
     * @param string|null $conditions condiciones SQL opcionales
     * @param array<mixed> $bindings bindings para las condiciones
     * @param string $orderBy campo para ordenar los resultados (importante para la paginación)
     */
    public static function findInBatches(
        string $table,
        callable $callback,
        int $batchSize = 1000,
        ?string $conditions = null,
        array $bindings = [],
        string $orderBy = 'id',
    ): void {
        if (! self::$ormInstance instanceof VersaORM) {
            throw new Exception('No ORM instance available. Call VersaModel::setORM() first.');
        }

        $offset = 0;

        while (true) {
            $query = self::$ormInstance->table($table, static::class)
                ->orderBy($orderBy)
                ->limit($batchSize)
                ->offset($offset);

            if (is_string($conditions) && trim($conditions) !== '') {
                $query->whereRaw($conditions, $bindings);
            }

            $models = $query->findAll();

            if (count($models) < 1) {
                break;
            }

            $callback($models);

            if ($batchSize > 0 && count($models) < $batchSize) {
                break;
            }

            $offset += $batchSize;
        }
    }

    /**
     * Guarda un modelo (método estático de conveniencia).
     */
    public static function storeModel(self $model): int|string|null
    {
        return $model->store();
    }

    /**
     * Guarda múltiples modelos en una sola operación lógica.
     * Recorre cada modelo y ejecuta store() acumulando los IDs retornados.
     * Si ocurre una excepción en medio del proceso se lanza y no se intenta continuar.
     * NOTA: Actualmente no se agrupa en una única transacción SQL (el núcleo Rust gestiona
     * las operaciones individuales). Futuro: optimizar usando insertMany cuando todos los
     * modelos sean nuevos y de la misma tabla.
     *
     * @param array<int,self> $models
     *
     * @throws VersaORMException
     *
     * @return array<int,int|string|null> IDs devueltos por cada store() en orden
     */
    public static function storeAll(array $models): array
    {
        if ($models === []) {
            return [];
        }

        foreach ($models as $i => $m) {
            if (! $m instanceof self) {
                throw new VersaORMException('storeAll expects an array of VersaModel instances at index ' . $i);
            }
        }
        // Detectar si todos son nuevos (sin PK) y de la misma tabla para intentar optimización insertMany
        /** @var self $first */
        $first = $models[0];
        $sameTable = true;
        $allNew = true;
        $table = $first->getTable();
        $pk = 'id'; // Asumimos 'id' como PK estándar (futuro: detectar dinámicamente)

        foreach ($models as $m) {
            if ($m->getTable() !== $table) {
                $sameTable = false;
                break;
            }
            if (isset($m->$pk) && $m->$pk !== null) {
                $allNew = false; // ya persistido
            }
        }

        // Si cumple condiciones usar insertMany para reducir viajes
        if ($sameTable && $allNew) {
            try {
                $records = [];
                foreach ($models as $m) {
                    $records[] = $m->getData();
                }
                $qb = self::orm()->table($table, static::class);
                $result = $qb->insertMany($records); // ahora puede devolver inserted_ids
                $insertedIds = $result['inserted_ids'] ?? [];
                if (is_array($insertedIds) && count($insertedIds) === count($models)) {
                    foreach ($models as $idx => $m) {
                        $m->id = $insertedIds[$idx];
                    }

                    return $insertedIds;
                }
                // Fallback: obtener IDs individuales (update no cambia datos)
                $fallbackIds = [];
                foreach ($models as $m) {
                    $fallbackIds[] = $m->store();
                }

                return $fallbackIds;
            } catch (Throwable $e) {
                // Fallback completo a inserciones individuales
            }
        }

        // Fallback general: insert/update uno a uno
        $ids = [];
        foreach ($models as $model) {
            $ids[] = $model->store();
        }

        return $ids;
    }

    /**
     * Elimina un modelo (método estático de conveniencia).
     */
    public static function trashModel(self $model): void
    {
        $model->trash();
    }

    /**
     * Elimina múltiples modelos de la base de datos.
     *
     * @param array<int,self> $models
     *
     * @throws VersaORMException
     */
    public static function trashAll(array $models): void
    {
        if ($models === []) {
            return;
        }
        foreach ($models as $i => $m) {
            if (! $m instanceof self) {
                throw new VersaORMException('trashAll espera un array de VersaModel en el índice ' . $i);
            }
            $m->trash();
        }
    }

    /**
     * Obtiene la instancia del ORM para uso en traits.
     *
     * @return array<string, mixed>|VersaORM|null
     */
    public function getOrm()
    {
        return $this->orm;
    }

    /**
     * Crea una nueva instancia del modelo con datos actualizados desde la base de datos.
     *
     * @param string $primaryKey Nombre de la clave primaria (default: 'id')
     *
     * @throws VersaORMException Si no se puede recargar el modelo
     *
     * @return static Nueva instancia del modelo con datos actualizados
     */
    public function fresh(string $primaryKey = 'id'): static
    {
        // Verificar que tenemos una instancia de ORM disponible
        $orm = $this->orm ?? self::$ormInstance;
        if (! ($orm instanceof VersaORM)) {
            throw new VersaORMException(
                'No ORM instance available for fresh operation',
                'NO_ORM_INSTANCE',
            );
        }

        // Verificar que el modelo tiene un ID para recargar
        $currentId = $this->getAttribute($primaryKey);
        if ($currentId === null) {
            throw new VersaORMException(
                'Cannot create fresh model without primary key value',
                'NO_PRIMARY_KEY_VALUE',
            );
        }

        // Crear nueva instancia usando findOne
        $freshModel = static::findOne($this->table, $currentId, $primaryKey);

        if ($freshModel === null) {
            throw new VersaORMException(
                'Model not found in database during fresh operation',
                'MODEL_NOT_FOUND',
            );
        }

        /** @phpstan-return static */
        /** @var static */
        return $freshModel;
    }

    /**
     * Disparar un evento y ejecutar listeners y métodos mágicos.
     *
     * @return bool true si la operación puede continuar, false si se cancela
     */
    /**
     * Disparar un evento y ejecutar listeners y métodos mágicos.
     *
     * @param array<string, mixed> $context
     *
     * @return bool true si la operación puede continuar, false si se cancela
     */
    protected function fireEvent(string $event, array $context = []): bool
    {
        $modelEvent = new ModelEvent($this, $context['original'] ?? [], $context['changes'] ?? []);
        // Listeners registrados
        $listeners = static::$eventListeners[$event] ?? [];
        foreach ($listeners as $listener) {
            $listener($this, $modelEvent);
            if ($modelEvent->cancel) {
                return false;
            }
        }
        // Métodos mágicos: beforeCreate, afterSave, etc.
        $magicMethod = static::eventToMagicMethod($event);
        if (method_exists($this, $magicMethod)) {
            $this->$magicMethod();
            if ($modelEvent->cancel) {
                return false;
            }
        }

        return ! $modelEvent->cancel;
    }

    /**
     * Convierte nombre de evento a método mágico.
     */
    protected static function eventToMagicMethod(string $event): string
    {
        $map = [
            'creating' => 'beforeCreate',
            'created' => 'afterCreate',
            'updating' => 'beforeUpdate',
            'updated' => 'afterUpdate',
            'deleting' => 'beforeDelete',
            'deleted' => 'afterDelete',
            'retrieved' => 'afterRetrieve',
            'saving' => 'beforeSave',
            'saved' => 'afterSave',
        ];

        return $map[$event] ?? '';
    }

    /** Acceso desde instancia ($this->orm / $this->db). */
    protected function getOrmInstance(): VersaORM
    {
        return self::orm();
    }

    /**
     * Filtra atributos basándose en las reglas de Mass Assignment.
     *
     * @param array<string, mixed> $attributes
     *
     * @throws VersaORMException
     *
     * @return array<string, mixed>
     */
    protected function filterFillableAttributes(array $attributes): array
    {
        // Si $fillable está definido y no está vacío, usar solo esos campos
        if (count($this->fillable) > 0) {
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
                        ['field' => $key, 'fillable' => $this->fillable],
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
                ['guarded' => $this->guarded, 'attempted_fields' => array_keys($attributes)],
            );
        }

        // Filtrar campos que no están en $guarded
        $filtered = [];

        foreach ($attributes as $key => $value) {
            if (! in_array($key, $this->guarded, true)) {
                $filtered[$key] = $value;
            } else {
                throw new VersaORMException(
                    "Field '{$key}' is guarded against mass assignment.",
                    'GUARDED_FIELD_ERROR',
                    null,
                    [],
                    ['field' => $key, 'guarded' => $this->guarded],
                );
            }
        }

        return $filtered;
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
            /**
             * @var array<string, array{
             *   is_required: bool,
             *   is_nullable: bool,
             *   is_auto_increment: bool,
             *   max_length: int|string|null,
             *   data_type: string,
             *   validation_rules: array<int,string>
             * }> $validationSchema
             */
            $validationSchema = $this->getTableValidationSchema();

            if (count($validationSchema) < 1) {
                // Si no podemos obtener el esquema, usar validaciones básicas
                return $this->basicSchemaValidation();
            }

            // Validar cada campo del modelo contra el esquema
            foreach ($this->attributes as $field => $value) {
                if (! isset($validationSchema[$field])) {
                    continue; // Campo no existe en el esquema
                }

                $columnSchema = $validationSchema[$field];
                $fieldErrors = $this->validateFieldAgainstSchema($field, $value, $columnSchema);
                $errors = array_merge($errors, $fieldErrors);
            }

            // Validar campos requeridos que no están presentes
            foreach ($validationSchema as $fieldName => $columnSchema) {
                if (
                    ($columnSchema['is_required'] ?? false)
                    && ! isset($this->attributes[$fieldName])
                    && ! ($columnSchema['is_auto_increment'] ?? false)
                ) {
                    $errors[] = "The {$fieldName} field is required.";
                }
            }
        } catch (VersaORMException) {
            // En caso de error al obtener el esquema, usar validación básica
            return $this->basicSchemaValidation();
        }

        return $errors;
    }

    /**
     * Obtiene el esquema de validación desde Rust.
     *
     * @throws VersaORMException
     *
     * @return array<string, array<string, mixed>>
     */
    protected function getTableValidationSchema(): array
    {
        $orm = $this->orm ?? self::$ormInstance;

        if (! $orm instanceof VersaORM) {
            throw new VersaORMException('No ORM instance available for schema validation');
        }

        try {
            // Llamar al esquema del CLI de Rust para obtener metadatos de la tabla
            $result = $orm->schema('columns', $this->table);

            if (is_array($result) && $result !== []) {
                return $this->processSchemaToValidationRules($result);
            }
        } catch (Exception) {
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
     *
     * @return array<string, array<string, mixed>>
     */
    protected function processSchemaToValidationRules(array $schemaColumns): array
    {
        /** @var array<string, array{
         *   is_required: bool,
         *   is_nullable: bool,
         *   is_auto_increment: bool,
         *   max_length: int|string|null,
         *   data_type: string,
         *   validation_rules: array<int,string>
         * }> $validationSchema
         */
        $validationSchema = [];

        foreach ($schemaColumns as $column) {
            if (! isset($column['column_name'])) {
                continue;
            }

            $columnName = (string) $column['column_name'];
            $dataType = strtolower((string) ($column['data_type'] ?? ''));
            $isNullable = ((string) ($column['is_nullable'] ?? 'YES')) === 'YES';
            $maxLength = $column['character_maximum_length'] ?? null;
            $isAutoIncrement = ((string) ($column['extra'] ?? '')) === 'auto_increment';
            $isRequired = ! $isNullable && ($column['column_default'] === null) && ! $isAutoIncrement;

            $validationRules = [];

            // Reglas basadas en el tipo de datos
            if ((str_contains($dataType, 'varchar') || str_contains($dataType, 'char')) && $maxLength) {
                $validationRules[] = "max:{$maxLength}";
            }

            // Para campos INTEGER que representan boolean, verificar si hay un tipo PHP definido como boolean
            $propertyTypes = static::getPropertyTypes();
            $phpType = $propertyTypes[$columnName]['type'] ?? null;

            if (str_contains($dataType, 'int') && ($phpType === 'boolean' || $phpType === 'bool')) {
                // No agregar regla 'numeric' para campos boolean (aplica a TINYINT, INTEGER, etc.)
            } elseif (str_contains($dataType, 'int')) {
                $validationRules[] = 'numeric';
            }

            if (str_contains($dataType, 'decimal') || str_contains($dataType, 'float') || str_contains($dataType, 'double')) {
                $validationRules[] = 'numeric';
            }

            // Agregar validación de email para campos que contienen 'email' en el nombre
            if (str_contains($columnName, 'email')) {
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
     * @param array<string, mixed> $columnSchema
     *
     * @return array<string>
     */
    protected function validateFieldAgainstSchema(string $field, mixed $value, array $columnSchema): array
    {
        $errors = [];

        // Validar si el campo es requerido
        if (($columnSchema['is_required'] ?? false) && ($value === null || $value === '')) {
            $errors[] = "The {$field} field is required.";

            return $errors; // No validar más si está vacío y es requerido
        }

        // Si el valor es null y la columna lo permite, no validar más
        if ($value === null && (bool) ($columnSchema['is_nullable'] ?? false)) {
            return $errors;
        }
        // Max length validation
        if (isset($columnSchema['max_length']) && $columnSchema['max_length'] > 0 && is_string($value) && strlen($value) > $columnSchema['max_length']) {
            $errors[] = "The {$field} may not be greater than {$columnSchema['max_length']} characters.";
        }
        $propertyTypes = static::getPropertyTypes();
        $phpType = $propertyTypes[$field]['type'] ?? null;
        if ($phpType) {
            switch ($phpType) {
                case 'boolean':
                case 'bool':
                    // Para boolean, aceptar bool, 0, 1, "0", "1", "true", "false"
                    if (! is_bool($value) && ! in_array($value, [0, 1, '0', '1', 'true', 'false', true, false], true)) {
                        $errors[] = "The {$field} must be a boolean value.";
                    }
                    break;

                case 'integer':
                case 'int':
                    if (! is_numeric($value) || (string) (int) $value !== (string) $value) {
                        $errors[] = "The {$field} must be an integer.";
                    }
                    break;
                case 'float':
                case 'double':
                case 'decimal':
                    // Aceptar cualquier valor numérico (int, float, string numérico)
                    if (! is_numeric($value)) {
                        $errors[] = "The {$field} must be a number.";
                    }
                    break;
                case 'string':
                    if (! is_string($value)) {
                        $errors[] = "The {$field} must be a string.";
                    }
                    break;

                case 'datetime':
                case 'date':
                case 'timestamp':
                    if (! ($value instanceof DateTime || $value instanceof DateTimeInterface || is_string($value))) {
                        $errors[] = "The {$field} must be a valid date.";
                    }
                    break;
            }
        } else {
            // Fallback: usar tipo de base de datos solo si no hay tipo PHP definido
            $dataType = strtolower($columnSchema['data_type'] ?? '');

            // Caso especial: TINYINT debería tratarse como boolean por defecto
            if ($dataType === 'tinyint') {
                if (! is_bool($value) && ! in_array($value, [0, 1, '0', '1', 'true', 'false', true, false], true)) {
                    $errors[] = "The {$field} must be a boolean value.";
                }
            } elseif (str_contains($dataType, 'int')) {
                if (! is_numeric($value) || (string) (int) $value !== (string) $value) {
                    $errors[] = "The {$field} must be an integer.";
                }
            } elseif (str_contains($dataType, 'decimal') || str_contains($dataType, 'float')) {
                if (! is_numeric($value)) {
                    $errors[] = "The {$field} must be a number.";
                }
            }
        }
        // Custom validation rules
        if (isset($columnSchema['validation_rules']) && is_array($columnSchema['validation_rules']) && $columnSchema['validation_rules'] !== []) {
            foreach ($columnSchema['validation_rules'] as $rule) {
                if ($rule === 'email' && is_string($value) && ! filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    $errors[] = "The {$field} must be a valid email address.";
                }
                // Add more rules as needed
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
            // Campos comunes que suelen ser auto-increment o tienen valores por defecto
            if (($value === '' || $value === null) && ! in_array($field, ['id', 'created_at', 'updated_at'], true)) {
                // Esta es una validación muy básica
                // En un proyecto real, esto se configuraría por modelo
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
            $value = $this->attributes[$field] ?? null;
            foreach ($rules as $rule) {
                $error = $this->validateSingleRule($field, $value, $rule);
                if (is_string($error) && $error !== '') {
                    $errors[] = $error;
                }
            }
        }

        return $errors;
    }

    /**
     * Summary of isValidJson.
     */
    protected function isValidJson(mixed $value): bool
    {
        if (is_string($value)) {
            json_decode($value);

            return json_last_error() === JSON_ERROR_NONE;
        }

        return false;
    }

    protected function isValidDate(mixed $value): bool
    {
        if ($value === null || (is_string($value) && $value === '')) {
            return false;
        }
        // Intentar parsear como fecha
        $date = DateTime::createFromFormat('Y-m-d', $value);
        if ($date instanceof DateTime && $date->format('Y-m-d') === $value) {
            return true;
        }
        // Intentar otros formatos comunes
        $formats = ['Y-m-d H:i:s', 'd/m/Y', 'm/d/Y', 'Y/m/d'];
        foreach ($formats as $format) {
            $date = DateTime::createFromFormat($format, $value);
            if ($date instanceof DateTime) {
                return true;
            }
        }

        return false;
    }

    /**
     * Valida una sola regla contra un campo.
     */
    protected function validateSingleRule(string $field, mixed $value, string $rule): ?string
    {
        switch ($rule) {
            case 'required':
                if ($value === null || $value === '') {
                    return "The {$field} field is required.";
                }
                break;

            case 'email':
                if (! filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    return "The {$field} must be a valid email address.";
                }
                break;
            case 'url':
                if (! filter_var($value, FILTER_VALIDATE_URL)) {
                    return "The {$field} must be a valid URL.";
                }
                break;
            case 'boolean':
                if (! is_bool($value) && ! in_array($value, [0, 1, '0', '1', 'true', 'false'], true)) {
                    return "The {$field} must be a boolean.";
                }
                break;

            case 'alpha':
                if (! preg_match('/^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$/', $value)) {
                    return "El {$field} solo puede contener letras.";
                }
                break;

            case 'alpha_num':
                if (! preg_match('/^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑ]+$/', $value)) {
                    return "El {$field} solo puede contener letras y números.";
                }
                break;

            case 'json':
                if (! $this->isValidJson($value)) {
                    return "El {$field} debe ser un JSON válido.";
                }
                break;

            case 'numeric':
                if (! is_numeric($value)) {
                    return "The {$field} must be numeric.";
                }
                break;
            case 'date':
                if (! $this->isValidDate($value)) {
                    return "El {$field} debe ser una fecha válida.";
                }
                break;

            case 'integer':
                if (! is_int($value) && (! is_string($value) || filter_var($value, FILTER_VALIDATE_INT) === false)) {
                    return "El {$field} debe ser un número entero.";
                }
                break;
            case 'uuid':
                if (! is_string($value) || ! $this->isValidUuid($value)) {
                    return "El {$field} debe ser un UUID válido.";
                }
                break;

            case 'ip':
                if (! is_string($value) || ! filter_var($value, FILTER_VALIDATE_IP)) {
                    return "El {$field} debe ser una dirección IP válida.";
                }
                break;

            default:
                // Reglas con parámetros (ej: 'max:255', 'min:3')
                if (str_contains($rule, ':')) {
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

                        case 'between':
                            [$min, $max] = explode(',', $parameter);
                            if (is_numeric($value) && ($value < $min || $value > $max)) {
                                return "El {$field} debe estar entre {$min} y {$max}.";
                            }
                            break;

                        case 'in':
                            $allowedValues = explode(',', $parameter);
                            if (! in_array($value, $allowedValues, true)) {
                                return "El {$field} debe ser uno de: " . implode(', ', $allowedValues);
                            }
                            break;

                        case 'not_in':
                            $disallowedValues = explode(',', $parameter);
                            if (in_array($value, $disallowedValues, true)) {
                                return "El {$field} no debe ser uno de: " . implode(', ', $disallowedValues);
                            }
                            break;
                        case 'regex':
                            if (! preg_match("/{$parameter}/", $value)) {
                                return "El {$field} no tiene el formato correcto.";
                            }
                            break;

                        case 'digits':
                            if (! is_string($value) || ! preg_match('/^\d{' . $parameter . '}$/', $value)) {
                                return "El {$field} debe tener exactamente {$parameter} dígitos.";
                            }
                            break;

                        case 'size':
                            if (is_string($value) && strlen($value) !== (int) $parameter) {
                                return "El {$field} debe tener exactamente {$parameter} caracteres.";
                            }
                            break;
                    }
                }
                break;
        }

        return null;
    }

    protected function getRelationName(): string
    {
        $class = new ReflectionClass($this);

        return strtolower($class->getShortName());
    }

    /**
     * Prepara un valor para ser enviado a la base de datos.
     * Convierte objetos DateTime a string y maneja otros tipos especiales.
     * Esta función es lo opuesto a castToPhpType - convierte de PHP a formato DB.
     *
     * @param string $field Nombre del campo para aplicar casting específico
     * @param mixed $value Valor a preparar
     *
     * @return mixed
     */
    private function prepareValueForDatabase(string $field, mixed $value)
    {
        // Si el valor es null, mantenerlo como null
        if ($value === null) {
            return null;
        }

        // Obtener el tipo PHP definido para este campo
        $propertyTypes = static::getPropertyTypes();
        $fieldType = $propertyTypes[$field]['type'] ?? null;

        // Convertir según el tipo PHP definido
        if ($fieldType) {
            switch ($fieldType) {
                case 'boolean':
                case 'bool':
                    // Convertir boolean a int para la base de datos (TINYINT)
                    if (is_bool($value)) {
                        return $value ? 1 : 0;
                    }

                    // Si no es boolean, convertir string/numeric a int
                    if (is_numeric($value)) {
                        return (float) $value != 0 ? 1 : 0;
                    }

                    return in_array(strtolower((string) $value), ['1', 'true', 'yes', 'on'], true) ? 1 : 0;

                case 'integer':
                case 'int':
                    return is_numeric($value) ? (int) $value : 0;

                case 'float':
                case 'double':
                case 'decimal':
                    return is_numeric($value) ? (float) $value : 0.0;

                case 'string':
                case 'uuid':
                    return (string) $value;

                case 'datetime':
                case 'date':
                case 'timestamp':
                    if ($value instanceof DateTime) {
                        return $value->format('Y-m-d H:i:s');
                    }

                    if ($value instanceof DateTimeInterface) {
                        return $value->format('Y-m-d H:i:s');
                    }

                    // Si es string, asumir que ya está en formato correcto
                    return $value;

                case 'json':
                case 'array':
                    if (is_array($value) || is_object($value)) {
                        return json_encode($value);
                    }

                    return $value;

                default:
                    // Para tipos no reconocidos, aplicar conversiones básicas
                    break;
            }
        }

        // Fallback: conversiones automáticas sin tipo específico
        if ($value instanceof DateTime) {
            return $value->format('Y-m-d H:i:s');
        }

        if ($value instanceof DateTimeInterface) {
            return $value->format('Y-m-d H:i:s');
        }

        if (is_bool($value)) {
            return $value ? 1 : 0;
        }

        if (is_array($value) || is_object($value)) {
            return json_encode($value);
        }

        return $value;
    }

    /**
     * Versión simplificada para compatibilidad hacia atrás.
     *
     * @return mixed
     */
    private function prepareValueForDatabaseSimple(mixed $value)
    {
        return $this->prepareValueForDatabase('unknown', $value);
    }

    /**
     * Crea una tabla base con una columna id si no existe.
     * Usada como fallback cuando no está en freeze y la tabla falta.
     */
    private function createBaseTableIfMissing(VersaORM $orm): void
    {
        try {
            $sql = "CREATE TABLE IF NOT EXISTS `{$this->table}` (id INTEGER PRIMARY KEY AUTOINCREMENT)";
            // Ajuste de sintaxis por driver
            $cfg = $orm->getConfig();
            $driver = strtolower((string) ($cfg['driver'] ?? $cfg['database_type'] ?? 'mysql'));

            if ($driver === 'mysql' || $driver === 'mariadb') {
                $sql = "CREATE TABLE IF NOT EXISTS `{$this->table}` (id INT AUTO_INCREMENT PRIMARY KEY) ENGINE=InnoDB";
            } elseif ($driver === 'pgsql' || $driver === 'postgres' || $driver === 'postgresql') {
                $sql = "CREATE TABLE IF NOT EXISTS \"{$this->table}\" (id SERIAL PRIMARY KEY)";
            }
            $orm->exec($sql);
        } catch (Throwable) {
            // Silencioso: si no se puede crear, dejar que el flujo normal falle
        }
    }

    /**
     * Verifica que todas las columnas del modelo existan en la tabla.
     * Si el modo freeze está desactivado, crea automáticamente las columnas faltantes.
     * Esta funcionalidad emula el comportamiento de RedBeanPHP.
     *
     * @param VersaORM $orm Instancia del ORM
     *
     * @throws VersaORMException
     */
    private function ensureColumnsExist(VersaORM $orm): void
    {
        // Solo verificar si freeze está desactivado (tanto global como por modelo)
        $modelClass = static::class;
        $isGloballyFrozen = $orm->isFrozen();
        $isModelFrozen = $orm->isModelFrozen($modelClass);

        if ($isGloballyFrozen || $isModelFrozen) {
            // Modo freeze activo - no crear columnas automáticamente
            return;
        }

        try {
            // Obtener columnas existentes de la tabla
            $existingColumns = $orm->schema('columns', $this->table);

            if (! is_array($existingColumns)) {
                // Si no se puede obtener la información del esquema, continuar sin validar
                return;
            }

            // Extraer solo los nombres de las columnas
            $existingColumnNames = [];

            foreach ($existingColumns as $column) {
                if (isset($column['name'])) {
                    // VersaORM devuelve 'name' como campo principal
                    $existingColumnNames[] = strtolower($column['name']);
                } elseif (isset($column['column_name'])) {
                    $existingColumnNames[] = strtolower($column['column_name']);
                } elseif (isset($column['Field'])) {
                    // MySQL usa 'Field' en lugar de 'column_name'
                    $existingColumnNames[] = strtolower($column['Field']);
                } elseif (is_string($column)) {
                    // Si solo es un string con el nombre
                    $existingColumnNames[] = strtolower($column);
                }
            }

            // Verificar qué campos del modelo no existen en la tabla
            $missingColumns = [];

            foreach ($this->attributes as $fieldName => $value) {
                // Saltar únicamente la PK 'id' (permitimos created_at/updated_at si el modelo los usa)
                if ($fieldName === 'id') {
                    continue;
                }

                if (! in_array(strtolower($fieldName), $existingColumnNames, true)) {
                    $missingColumns[$fieldName] = $this->inferColumnType($value);
                }
            }

            // Debug log
            error_log("VersaORM: Table '{$this->table}' existing columns: " . implode(', ', $existingColumnNames));
            error_log('VersaORM: Model attributes: ' . implode(', ', array_keys($this->attributes)));
            error_log('VersaORM: Missing columns to create: ' . implode(', ', array_keys($missingColumns)));

            // Crear columnas faltantes
            foreach ($missingColumns as $columnName => $columnType) {
                error_log("VersaORM: Attempting to create column '{$columnName}' ({$columnType}) in table '{$this->table}'");
                $this->createColumn($orm, $columnName, $columnType);
            }
        } catch (Exception $e) {
            // Si la tabla no existe, intentar crearla y continuar
            $msg = strtolower($e->getMessage());

            if (str_contains($msg, 'no such table') || str_contains($msg, "doesn't exist") || str_contains($msg, 'base table or view not found')) {
                $this->createBaseTableIfMissing($orm);

                // Intentar nuevamente obtener columnas tras crear la tabla y crear las faltantes
                try {
                    $existingColumns = $orm->schema('columns', $this->table);

                    if (! is_array($existingColumns)) {
                        return;
                    }
                    $existingColumnNames = [];

                    foreach ($existingColumns as $column) {
                        if (isset($column['name'])) {
                            $existingColumnNames[] = strtolower($column['name']);
                        } elseif (isset($column['column_name'])) {
                            $existingColumnNames[] = strtolower($column['column_name']);
                        } elseif (isset($column['Field'])) {
                            $existingColumnNames[] = strtolower($column['Field']);
                        } elseif (is_string($column)) {
                            $existingColumnNames[] = strtolower($column);
                        }
                    }
                    $missingColumns = [];

                    foreach ($this->attributes as $fieldName => $value) {
                        if ($fieldName === 'id') {
                            continue;
                        }

                        if (! in_array(strtolower($fieldName), $existingColumnNames, true)) {
                            $missingColumns[$fieldName] = $this->inferColumnType($value);
                        }
                    }

                    foreach ($missingColumns as $columnName => $columnType) {
                        $this->createColumn($orm, $columnName, $columnType);
                    }
                } catch (Throwable) {
                    return; // si aún falla, salir silenciosamente
                }
            } else {
                // Otros errores: loguear y continuar
                error_log("VersaORM: Error verificando columnas para {$this->table}: " . $e->getMessage());
            }
        }
    }

    /**
     * Infiere el tipo de columna basado en el valor PHP.
     *
     * @param mixed $value Valor para inferir el tipo
     *
     * @return string Tipo de columna SQL
     */
    private function inferColumnType(mixed $value): string
    {
        if ($value === null) {
            return 'VARCHAR(255)'; // Tipo por defecto para valores null
        }

        // Mapear DateTime a tipo de fecha
        if ($value instanceof DateTime) {
            return 'DATETIME';
        }

        if (is_bool($value)) {
            return 'BOOLEAN';
        }

        if (is_int($value)) {
            return 'INT';
        }

        if (is_float($value)) {
            return 'DECIMAL(10,2)';
        }

        if (is_string($value)) {
            $length = strlen($value);

            if ($length <= 255) {
                return 'VARCHAR(255)';
            }

            if ($length <= 65535) {
                return 'TEXT';
            }

            return 'LONGTEXT';
        }

        if (is_array($value) || is_object($value)) {
            return 'JSON';
        }

        // Tipo por defecto
        return 'VARCHAR(255)';
    }

    /**
     * Crea una nueva columna en la tabla.
     *
     * @param VersaORM $orm Instancia del ORM
     * @param string $columnName Nombre de la columna
     * @param string $columnType Tipo de la columna
     *
     * @throws VersaORMException
     */
    private function createColumn(VersaORM $orm, string $columnName, string $columnType): void
    {
        $sql = null;

        try {
            // Construir la consulta ALTER TABLE
            $sql = "ALTER TABLE `{$this->table}` ADD COLUMN `{$columnName}` {$columnType}";

            // Ejecutar la consulta
            $orm->exec($sql);

            // Log de la creación automática de columna
            error_log("VersaORM: Created column '{$columnName}' ({$columnType}) in table '{$this->table}'");
        } catch (Exception $e) {
            throw new VersaORMException(
                "Failed to create column '{$columnName}' in table '{$this->table}': " . $e->getMessage(),
                'COLUMN_CREATION_FAILED',
                $sql,
                [],
                [
                    'table' => $this->table,
                    'column' => $columnName,
                    'type' => $columnType,
                    'sql' => $sql,
                ],
            );
        }
    }
}
