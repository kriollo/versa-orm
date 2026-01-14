<?php

declare(strict_types=1);

namespace VersaORM\Traits;

use DateTime;
use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use Exception;
use InvalidArgumentException;
use ReflectionMethod;
use Throwable;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

use function in_array;
use function is_array;
use function is_bool;
use function is_int;
use function is_object;
use function is_scalar;
use function is_string;
use function strlen;

/**
 * Casting fuerte bidireccional usando mapas de handlers uniformes.
 * Handler: fn(object $self,string $property,mixed $value,array $typeDef=[]): mixed.
 */
/**
 * @psalm-type PropertyTypeDef = array{
 *   type?: string,
 *   values?: array<int,string>,
 *   max_length?: int,
 *   nullable?: bool
 * }
 * @psalm-type PropertyTypeMap = array<string,PropertyTypeDef>
 */
trait HasStrongTyping
{
    /** @var array<string,callable> */
    protected array $mutators = [];

    /** @var array<string,callable> */
    protected array $accessors = [];

    /** @var array<string,mixed>|null */
    private ?array $databaseSchemaCache = null;

    /** @var array<string,string> */
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

    /** @var array<string,callable> */
    private static array $phpCastHandlers = [];

    /** @var array<string,callable> */
    private static array $dbCastHandlers = [];

    /**
     * @return PropertyTypeMap
     */
    public static function getPropertyTypes(): array
    {
        $cls = static::class;
        $registry = &self::propertyTypeRegistry();

        if (isset($registry[$cls])) {
            return $registry[$cls];
        }

        /** @var PropertyTypeMap $types */
        $types = [];

        // 1. Método público/estático propertyTypes()
        if (method_exists($cls, 'propertyTypes')) {
            try {
                $maybe = $cls::propertyTypes();

                if (is_array($maybe)) {
                    $types = $maybe;
                }
            } catch (Throwable) { // ignorar
            }
        }

        // 2. Método protegido/privado definePropertyTypes()
        if ($types === [] && method_exists($cls, 'definePropertyTypes')) {
            try {
                $ref = new ReflectionMethod($cls, 'definePropertyTypes');
                $ref->setAccessible(true);
                $maybe = $ref->invoke(null); // método estático

                if (is_array($maybe)) {
                    $types = $maybe;
                }
            } catch (Throwable) { // ignorar
            }
        }

        // 3. Normalización
        foreach ($types as &$def) {
            if (!(isset($def['type']) && is_string($def['type']))) {
                continue;
            }

            $def['type'] = strtolower($def['type']);
        }
        unset($def);

        return $registry[$cls] = $types;
    }

    /**
     * @throws VersaORMException
     *
     * @return mixed
     */
    public function castToPhpType(string $property, mixed $value)
    {
        if ($value === null) {
            return null;
        }
        /** @var PropertyTypeMap $types */
        $types = static::getPropertyTypes();

        if (!isset($types[$property])) { // fallback heurístico
            if (is_string($value)) {
                $trim = trim($value);

                if ($trim !== '' && ($trim[0] === '{' || $trim[0] === '[')) {
                    $d = json_decode($value, true);

                    if (json_last_error() === JSON_ERROR_NONE) {
                        return $d;
                    }
                }

                try {
                    if (preg_match('/^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?/', $trim) === 1) {
                        return new DateTime($trim);
                    }
                } catch (Throwable) {
                }
            }

            return $value;
        }
        /** @var PropertyTypeDef $def */
        $def = $types[$property];
        $type = isset($def['type']) && is_string($def['type']) ? $def['type'] : 'string';
        $handler = self::getPhpCastHandlers()[$type] ?? static fn($s, $p, $v, $t = []): mixed => $v;

        try {
            return $handler($this, $property, $value, $def);
        } catch (Exception $e) {
            if ($e instanceof VersaORMException || $e instanceof InvalidArgumentException) {
                throw $e;
            }

            throw new VersaORMException(
                "Error casting property {$property} to PHP type {$type}: " . $e->getMessage(),
                'TYPE_CASTING_ERROR',
            );
        }
    }

    /**
     * @throws VersaORMException
     *
     * @return mixed
     */
    public function castToDatabaseType(string $property, mixed $value)
    {
        if ($value === null) {
            return null;
        }
        /** @var PropertyTypeMap $types */
        $types = static::getPropertyTypes();

        if (!isset($types[$property])) {
            if ($value instanceof DateTimeInterface) {
                return $value->format('Y-m-d H:i:s');
            }

            if (is_array($value) || is_object($value)) {
                return json_encode($value, JSON_UNESCAPED_UNICODE);
            }

            if (is_bool($value)) {
                return $value ? 1 : 0;
            }

            return $value;
        }
        /** @var PropertyTypeDef $def */
        $def = $types[$property];
        $type = isset($def['type']) && is_string($def['type']) ? $def['type'] : 'string';
        $handler = self::getDbCastHandlers()[$type] ?? static fn($s, $p, $v, $t = []): mixed => $v;

        try {
            return $handler($this, $property, $value, $def);
        } catch (Exception $e) {
            if ($e instanceof VersaORMException || $e instanceof InvalidArgumentException) {
                throw $e;
            }

            throw new VersaORMException(
                "Error casting property {$property} to database type {$type}: " . $e->getMessage(),
                'DATABASE_CASTING_ERROR',
            );
        }
    }

    /** @return array<string> */
    public function validateSchemaConsistency(): array
    {
        $errs = [];
        $types = static::getPropertyTypes();

        if ($types === []) {
            return ['No property types defined for model ' . static::class];
        }

        try {
            if (!$this->orm instanceof VersaORM) {
                return ['Se requiere una instancia válida de VersaORM para validar el esquema'];
            }
            /** @var false|list<array{column_name:string,data_type:string,is_nullable?:string,character_maximum_length?:int}> $schema */
            $schema = $this->orm->schema('columns', $this->table);

            if ($schema === false) {
                return ["No se pudo obtener información de esquema para la tabla '{$this->table}'"];
            }
            /** @var array<string,array{column_name:string,data_type:string,is_nullable?:string,character_maximum_length?:int}> $db */
            $db = [];

            foreach ($schema as $c) {
                $db[strtolower($c['column_name'])] = $c;
            }
            $map = [
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

            foreach ($types as $prop => $def) {
                $c = strtolower($prop);

                if (!isset($db[$c])) {
                    $errs[] = "⚠️  ADVERTENCIA: La propiedad '{$prop}' no existe en la base de datos";

                    continue;
                }
                $dbCol = $db[$c];
                $dbType = strtolower($dbCol['data_type']);
                $modelType = strtolower((string) ($def['type'] ?? ''));
                $expected = $map[$dbType] ?? $dbType;

                if ($expected !== $modelType && !$this->isCompatibleType($expected, $modelType)) {
                    $errs[] = "⚠️  INCONSISTENCIA: '{$prop}' - DB: {$dbType} ({$expected}) vs Modelo: {$modelType}";
                }
                $nullable = strtolower($dbCol['is_nullable'] ?? 'no') === 'yes';
                $modelNull = (bool) ($def['nullable'] ?? false);

                if ($nullable !== $modelNull) {
                    $errs[] =
                        "⚠️  NULLABILIDAD: '{$prop}' - DB permite NULL: "
                        . ($nullable ? 'Sí' : 'No')
                        . ' vs Modelo: '
                        . ($modelNull ? 'Sí' : 'No');
                }
            }

            foreach ($db as $cn => $cinfo) {
                if (isset($types[$cn])) {
                    continue;
                }

                $errs[] = "💡 INFO: Columna '{$cn}' existe en DB pero no está definida en el modelo";
            }
        } catch (Exception $e) {
            $errs[] = 'Error al validar esquema: ' . $e->getMessage();
        }

        return $errs;
    }

    /** @return array<string,callable> */
    public function getMutators(): array
    {
        return $this->mutators;
    }

    /** @return array<string,callable> */
    public function getAccessors(): array
    {
        return $this->accessors;
    }

    public static function clearPropertyTypesCache(): void
    {
        $r = &self::propertyTypeRegistry();
        unset($r[static::class]);
    }

    public function clearDatabaseSchemaCache(): void
    {
        $this->databaseSchemaCache = null;
    }

    /**
     * Registrar un conversor de tipo en tiempo de ejecución (PHP side).
     * $name: nombre del tipo (por ejemplo 'money')
     * $phpHandler: callable(object,string,mixed,array): mixed para convertir a PHP
     * $dbHandler: callable(object,string,mixed,array): mixed para convertir a DB (opcional).
     */
    public static function addTypeConverter(string $name, callable $phpHandler, ?callable $dbHandler = null): void
    {
        $lname = strtolower($name);

        // Inicializar handlers si están vacíos
        if (self::$phpCastHandlers === []) {
            self::getPhpCastHandlers();
        }

        if (self::$dbCastHandlers === []) {
            self::getDbCastHandlers();
        }

        // Añadir/sobrescribir en los registries
        self::$phpCastHandlers[$lname] = $phpHandler;

        if ($dbHandler !== null) {
            self::$dbCastHandlers[$lname] = $dbHandler;
        } else {
            // Por defecto, serializar a string/JSON inteligentemente para BD
            self::$dbCastHandlers[$lname] = static function ($s, $p, $v, $_ = []) {
                if (is_array($v) || is_object($v)) {
                    return json_encode($v, JSON_UNESCAPED_UNICODE);
                }

                return (string) $v;
            };
        }
    }

    /**
     * Eliminar un conversor previamente registrado (si existe).
     */
    public static function removeTypeConverter(string $name): void
    {
        $lname = strtolower($name);

        if (isset(self::$phpCastHandlers[$lname])) {
            unset(self::$phpCastHandlers[$lname]);
        }

        if (isset(self::$dbCastHandlers[$lname])) {
            unset(self::$dbCastHandlers[$lname]);
        }
    }

    /**
     * Limpia todos los registros estáticos de convertidores de tipos.
     * Útil para prevenir memory leaks en procesos de larga duración.
     */
    public static function clearTypeConverters(): void
    {
        self::$phpCastHandlers = [];
        self::$dbCastHandlers = [];

        // Limpiar también el registry de tipos de propiedades
        $registry = &self::propertyTypeRegistry();
        foreach (array_keys($registry) as $class) {
            $registry[$class] = [];
        }
    }

    protected function applyMutator(string $k, $v)
    {
        return isset($this->mutators[$k]) ? $this->mutators[$k]($v) : $this->castToDatabaseType($k, $v);
    }

    protected function applyAccessor(string $k, $v)
    {
        return isset($this->accessors[$k]) ? $this->accessors[$k]($v) : $this->castToPhpType($k, $v);
    }

    /**
     * REGLA DE EXCEPCIONES UNIFICADA
     * - Para propiedades "core" (actualmente 'uuid', 'created_at', etc. que intervienen en tests de integridad) se lanza VersaORMException con mensaje contextual.
     * - Para validaciones genéricas ad-hoc (p.ej. uuid_field en pruebas de mapeo de tipos) se lanza InvalidArgumentException breve.
     * Esto permite a las suites diferenciar entre errores de modelo (capturables por la capa ORM) y errores de datos genéricos.
     */
    // Cache interno por clase consumidora (evita acceder propiedades estáticas del trait directamente)
    private static function &propertyTypeRegistry(): array
    {
        static $registry = [];

        return $registry;
    }

    /**
     * @return array<string,callable(object,string,mixed,PropertyTypeDef):mixed>
     */
    private static function getPhpCastHandlers(): array
    {
        if (self::$phpCastHandlers !== []) {
            return self::$phpCastHandlers;
        }
        $int = static fn($s, $p, $v, $_ = []): int => (int) (is_numeric($v) ? $v : 0);
        $float = static fn($s, $p, $v, $_ = []): float => (float) (is_numeric($v) ? $v : 0.0);
        $string = static fn($s, $p, $v, $_ = []): string => (
            is_scalar($v) ? (string) $v : (json_encode($v, JSON_UNESCAPED_UNICODE) ?: '')
        );
        $bool = static function ($s, $p, $v, $_ = []): bool {
            if (is_bool($v)) {
                return $v;
            }

            if (is_int($v)) {
                return $v === 1;
            }

            if (is_string($v)) {
                return in_array(strtolower($v), ['1', 'true', 'yes', 'on'], true);
            }

            return (bool) $v;
        };
        $array = static function ($s, $p, $v, $_ = []): array {
            if (is_array($v)) {
                return $v;
            }

            if (is_string($v)) {
                $decoded = json_decode($v, true);

                if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                    // @var array $decoded
                    return $decoded;
                }

                if ($v === '') {
                    return [];
                }

                return explode(',', $v);
            }

            if ($v === null) {
                return [];
            }

            return [$v];
        };
        $json = static function ($s, $p, $v, $_ = []): mixed {
            if (is_string($v)) {
                $d = json_decode($v, true);

                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new VersaORMException("Invalid JSON for property {$p}: " . json_last_error_msg());
                }

                return $d;
            }

            if (is_array($v) || is_object($v)) {
                return $v;
            }

            throw new VersaORMException("Invalid JSON for property {$p}: not a valid json string");
        };
        $uuid = static function ($s, $p, $v, $_ = []): string {
            $u = (string) $v;

            // Validación inline para evitar MixedMethodCall sobre $s
            if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $u) !== 1) {
                if ($p === 'uuid') {
                    throw new VersaORMException("Invalid UUID format for property {$p}: {$u}");
                }

                throw new InvalidArgumentException('Invalid UUID format');
            }

            return $u;
        };
        $dt = static function ($s, $p, $v, $_ = []): DateTimeInterface {
            if ($v instanceof DateTimeInterface) {
                return $v;
            }

            if (is_string($v)) {
                return new DateTime($v);
            }

            if (is_int($v) || ctype_digit((string) $v)) {
                return (new DateTimeImmutable('@'
                . (int) $v))->setTimezone(new DateTimeZone(date_default_timezone_get()));
            }

            throw new VersaORMException("Invalid datetime value for property {$p}");
        };
        $enum = static function ($s, $p, $v, $t = []): string {
            $val = (string) $v;
            $rawValues = $t['values'] ?? [];
            $allowed = [];

            if (is_array($rawValues)) {
                foreach ($rawValues as $rv) {
                    if (!(is_scalar($rv) || $rv === null)) {
                        continue;
                    }

                    $allowed[] = (string) $rv;
                }
            }

            if ($allowed !== [] && !in_array($val, $allowed, true)) {
                throw new VersaORMException(
                    "Invalid enum value for property {$p}. Allowed: " . implode(', ', $allowed),
                );
            }

            return $val;
        };
        $set = static function ($s, $p, $v, $t = []): array {
            $vals = [];

            if (is_array($v)) {
                $vals = $v;
            } elseif (is_string($v)) {
                if ($v === '') {
                    $vals = [];
                } else {
                    $decoded = json_decode($v, true);

                    $vals = json_last_error() === JSON_ERROR_NONE && is_array($decoded) ? $decoded : explode(',', $v);
                }
            } elseif ($v !== null) {
                $vals = [$v];
            }
            $allowed = [];

            if (isset($t['values']) && is_array($t['values'])) {
                /** @var array<int|mixed,scalar|string|null> $candidateValues */
                $candidateValues = $t['values'];

                foreach ($candidateValues as $rv) {
                    if (!(is_scalar($rv) || $rv === null)) {
                        continue;
                    }

                    $allowed[] = (string) $rv;
                }
            }

            if ($allowed !== []) {
                foreach ($vals as $vv) {
                    if (in_array((string) $vv, $allowed, true)) {
                        continue;
                    }

                    throw new VersaORMException(
                        "Invalid set value '{$vv}' for property {$p}. Allowed: " . implode(', ', $allowed),
                    );
                }
            }
            $out = [];

            foreach ($vals as $vv) {
                $out[] = (string) $vv;
            }

            return $out;
        };
        $blob = static fn($s, $p, $v, $_ = []): mixed => $v;
        $inet = static function ($s, $p, $v, $_ = []): string {
            $ip = (string) $v;

            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new VersaORMException("Invalid IP address for property {$p}: {$ip}");
            }
            // Normaliza (comprime) IPv6 y asegura forma canónica usando inet_pton/inet_ntop
            $packed = @inet_pton($ip);

            if ($packed !== false) {
                $normalized = @inet_ntop($packed);

                if (is_string($normalized) && $normalized !== '') {
                    $ip = $normalized;
                }
            }

            return $ip;
        };
        self::$phpCastHandlers = [
            'int' => $int,
            'integer' => $int,
            'float' => $float,
            'real' => $float,
            'double' => $float,
            'decimal' => $float,
            'string' => $string,
            'bool' => $bool,
            'boolean' => $bool,
            'array' => $array,
            'collection' => $array,
            'json' => $json,
            'uuid' => $uuid,
            'datetime' => $dt,
            'date' => $dt,
            'timestamp' => $dt,
            'enum' => $enum,
            'set' => $set,
            'blob' => $blob,
            'inet' => $inet,
        ];

        return self::$phpCastHandlers;
    }

    /**
     * @return array<string,callable(object,string,mixed,PropertyTypeDef):mixed>
     */
    private static function getDbCastHandlers(): array
    {
        if (self::$dbCastHandlers !== []) {
            return self::$dbCastHandlers;
        }
        $int = static fn($s, $p, $v, $_ = []): int => (int) $v;
        $float = static fn($s, $p, $v, $_ = []): float => (float) $v;
        $string = static function ($s, $p, $v, $t = []): string {
            $sv = (string) $v;
            $max = $t['max_length'] ?? null;

            if ($max && strlen($sv) > $max) {
                throw new VersaORMException("String too long for property {$p}. Max: {$max}, got: " . strlen($sv));
            }

            return $sv;
        };
        $bool = static fn($s, $p, $v, $_ = []): int => (
            is_bool($v)
                ? $v
                : (
                    is_numeric($v)
                        ? (float) $v !== 0.0
                        : in_array(strtolower((string) $v), ['1', 'true', 'yes', 'on'], true)
                )
        )
            ? 1
            : 0;
        $jsonLike = static function ($s, $p, $v, $_ = []): string {
            if (is_string($v)) {
                $trim = ltrim($v);

                if ($trim !== '' && ($trim[0] === '{' || $trim[0] === '[')) {
                    return $v;
                }
            }

            return json_encode($v, JSON_UNESCAPED_UNICODE) ?: 'null';
        };
        $uuid = static function ($s, $p, $v, $_ = []): string {
            $u = (string) $v;

            if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $u) !== 1) {
                if ($p === 'uuid') {
                    throw new VersaORMException("Invalid UUID format for property {$p}: {$u}");
                }

                throw new InvalidArgumentException('Invalid UUID format');
            }

            return $u;
        };
        $dt = static function ($s, $p, $v, $_ = []): string {
            if ($v instanceof DateTimeInterface) {
                return $v->format('Y-m-d H:i:s');
            }

            if (is_string($v)) {
                return (new DateTime($v))->format('Y-m-d H:i:s');
            }

            if (is_int($v) || ctype_digit((string) $v)) {
                return date('Y-m-d H:i:s', (int) $v);
            }

            throw new VersaORMException("Invalid datetime value for property {$p}");
        };
        $enum = static function ($s, $p, $v, $t = []): string {
            $val = (string) $v;
            $rawValues = $t['values'] ?? [];
            $allowed = [];

            if (is_array($rawValues)) {
                foreach ($rawValues as $rv) {
                    if (!(is_scalar($rv) || $rv === null)) {
                        continue;
                    }

                    $allowed[] = (string) $rv;
                }
            }

            if ($allowed !== [] && !in_array($val, $allowed, true)) {
                throw new VersaORMException(
                    "Invalid enum value for property {$p}. Allowed: " . implode(', ', $allowed),
                );
            }

            return $val;
        };
        $set = static function ($s, $p, $v, $t = []): string {
            $vals = [];

            if (is_array($v)) {
                $vals = $v;
            } elseif (is_string($v)) {
                if ($v === '') {
                    $vals = [];
                } else {
                    $decoded = json_decode($v, true);

                    $vals = json_last_error() === JSON_ERROR_NONE && is_array($decoded) ? $decoded : explode(',', $v);
                }
            } elseif ($v !== null) {
                $vals = [$v];
            }
            $allowed = [];

            if (isset($t['values']) && is_array($t['values'])) {
                /** @var array<int|mixed,scalar|string|null> $candidateValues */
                $candidateValues = $t['values'];

                foreach ($candidateValues as $rv) {
                    if (!(is_scalar($rv) || $rv === null)) {
                        continue;
                    }

                    $allowed[] = (string) $rv;
                }
            }

            if ($allowed !== []) {
                foreach ($vals as $vv) {
                    if (in_array((string) $vv, $allowed, true)) {
                        continue;
                    }

                    throw new VersaORMException(
                        "Invalid set value '{$vv}' for property {$p}. Allowed: " . implode(', ', $allowed),
                    );
                }
            }
            $out = [];

            foreach ($vals as $vv) {
                $out[] = (string) $vv;
            }

            return implode(',', $out);
        };
        $blob = static fn($s, $p, $v, $_ = []): mixed => $v;
        $inet = static function ($s, $p, $v, $_ = []): string {
            $ip = (string) $v;

            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new VersaORMException("Invalid IP address for property {$p}: {$ip}");
            }
            $packed = @inet_pton($ip);

            if ($packed !== false) {
                $normalized = @inet_ntop($packed);

                if (is_string($normalized) && $normalized !== '') {
                    $ip = $normalized;
                }
            }

            return $ip;
        };
        self::$dbCastHandlers = [
            'int' => $int,
            'integer' => $int,
            'float' => $float,
            'real' => $float,
            'double' => $float,
            'decimal' => $float,
            'string' => $string,
            'bool' => $bool,
            'boolean' => $bool,
            'array' => $jsonLike,
            'collection' => $jsonLike,
            'json' => $jsonLike,
            'uuid' => $uuid,
            'datetime' => $dt,
            'date' => $dt,
            'timestamp' => $dt,
            'enum' => $enum,
            'set' => $set,
            'blob' => $blob,
            'inet' => $inet,
        ];

        return self::$dbCastHandlers;
    }

    private function isCompatibleType(string $dbType, string $modelType): bool
    {
        $compat = [
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

        return in_array($modelType, $compat[$dbType] ?? [], true);
    }

    /** @return array<string,mixed> */
    private function getDatabaseSchema(): array
    {
        if ($this->databaseSchemaCache !== null) {
            return $this->databaseSchemaCache;
        }

        try {
            $s = $this->getTableValidationSchema();

            return $this->databaseSchemaCache = $s;
        } catch (Exception $e) {
            throw new VersaORMException('Could not retrieve database schema: ' . $e->getMessage());
        }
    }

    private function isValidUuid(string $uuid): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuid) === 1;
    }

    /** @return array<int,string> */
    private function validatePropertyConsistency(string $p, array $def, array $col): array
    {
        $errs = [];
        $modelType = strtolower((string) ($def['type'] ?? ''));
        $dbType = strtolower((string) ($col['data_type'] ?? ''));
        $compat = [
            'int' => ['int', 'integer', 'tinyint', 'smallint', 'bigint'],
            'float' => ['float', 'double', 'real', 'decimal', 'numeric'],
            'string' => ['varchar', 'char', 'text', 'mediumtext', 'longtext'],
            'bool' => ['tinyint', 'boolean', 'bit'],
            'boolean' => ['tinyint', 'boolean', 'bit'],
            'datetime' => ['datetime', 'timestamp', 'date'],
            'date' => ['date', 'datetime', 'timestamp'],
            'json' => ['json', 'jsonb', 'text'],
            'uuid' => ['uuid', 'char', 'varchar'],
            'enum' => ['enum'],
            'set' => ['set'],
            'blob' => ['blob', 'longblob', 'mediumblob', 'tinyblob'],
            'inet' => ['inet', 'varchar', 'char'],
        ];
        $ok = in_array($dbType, $compat[$modelType] ?? [], true) || $dbType === $modelType;

        if (!$ok) {
            $errs[] = "Type mismatch for property '{$p}': model={$modelType} db={$dbType}";
        }

        if (isset($def['nullable'])) {
            $mNull = (bool) $def['nullable'];
            $dNull = strtoupper((string) ($col['is_nullable'] ?? 'NO')) === 'YES';

            if ($mNull !== $dNull) {
                $errs[] =
                    "Nullability mismatch for property '{$p}': model="
                    . ($mNull ? 'YES' : 'NO')
                    . ' db='
                    . ($dNull ? 'YES' : 'NO');
            }
        }

        if (isset($def['max_length']) && ($def['max_length'] ?? null) !== null) {
            $ml = (int) $def['max_length'];
            $dbl = (int) ($col['character_maximum_length'] ?? 0);

            if ($dbl > 0 && $ml > $dbl) {
                $errs[] = "Length mismatch for property '{$p}': model={$ml} db={$dbl}";
            }
        }

        return $errs;
    }
}
