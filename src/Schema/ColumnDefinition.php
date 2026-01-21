<?php

declare(strict_types=1);

namespace VersaORM\Schema;

/**
 * ColumnDefinition representa la definición de una columna individual con sus modificadores.
 *
 * Esta clase proporciona una API fluida para definir columnas con todos sus atributos
 * como tipo, longitud, nullable, default, índices, etc.
 */
class ColumnDefinition
{
    protected string $name;

    protected string $type;

    /** @var array<string, mixed> */
    protected array $attributes = [];

    /** @var array<int, string> */
    protected array $modifiers = [];

    protected ?Blueprint $blueprint = null;

    /** @var ForeignKeyDefinition|null La última foreign key creada por esta columna */
    protected ?ForeignKeyDefinition $lastForeignKey = null;

    public function __construct(string $name, string $type, ?Blueprint $blueprint = null)
    {
        $this->name = $name;
        $this->type = $type;
        $this->blueprint = $blueprint;
    }

    /**
     * Obtiene el nombre de la columna.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Obtiene el tipo de la columna.
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * Obtiene todos los atributos de la columna.
     *
     * @return array<string, mixed>
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * Obtiene un atributo específico.
     */
    public function getAttribute(string $key, mixed $default = null): mixed
    {
        return $this->attributes[$key] ?? $default;
    }

    /**
     * Establece un atributo.
     */
    public function setAttribute(string $key, mixed $value): self
    {
        $this->attributes[$key] = $value;

        return $this;
    }

    /**
     * Obtiene todos los modificadores de la columna.
     *
     * @return array<int, string>
     */
    public function getModifiers(): array
    {
        return $this->modifiers;
    }

    // Modificadores de columna

    /**
     * Permite valores NULL en la columna.
     */
    public function nullable(bool $value = true): self
    {
        $this->attributes['nullable'] = $value;

        return $this;
    }

    /**
     * Establece un valor por defecto para la columna.
     */
    public function default(mixed $value): self
    {
        $this->attributes['default'] = $value;

        return $this;
    }

    /**
     * Marca la columna como autoincremental.
     */
    public function autoIncrement(): self
    {
        $this->attributes['autoIncrement'] = true;

        return $this;
    }

    /**
     * Marca la columna como clave primaria.
     */
    public function primary(): self
    {
        $this->attributes['primary'] = true;
        if ($this->blueprint !== null) {
            $this->blueprint->addIndex('primary', [$this->name]);
        }

        return $this;
    }

    /**
     * Crea un índice único en la columna.
     */
    public function unique(?string $indexName = null): self
    {
        if ($this->blueprint !== null) {
            $this->blueprint->addIndex('unique', [$this->name], $indexName);
        }

        return $this;
    }

    /**
     * Crea un índice en la columna.
     */
    public function index(?string $indexName = null): self
    {
        if ($this->blueprint !== null) {
            $this->blueprint->addIndex('index', [$this->name], $indexName);
        }

        return $this;
    }

    /**
     * Marca la columna como unsigned (solo para enteros).
     */
    public function unsigned(): self
    {
        $this->attributes['unsigned'] = true;

        return $this;
    }

    /**
     * Añade un comentario a la columna.
     */
    public function comment(string $comment): self
    {
        $this->attributes['comment'] = $comment;

        return $this;
    }

    /**
     * Especifica el charset de la columna (MySQL).
     */
    public function charset(string $charset): self
    {
        $this->attributes['charset'] = $charset;

        return $this;
    }

    /**
     * Especifica la collation de la columna (MySQL).
     */
    public function collation(string $collation): self
    {
        $this->attributes['collation'] = $collation;

        return $this;
    }

    /**
     * Posiciona la columna después de otra columna específica (MySQL).
     */
    public function after(string $column): self
    {
        $this->attributes['after'] = $column;

        return $this;
    }

    /**
     * Posiciona la columna al principio de la tabla (MySQL).
     */
    public function first(): self
    {
        $this->attributes['first'] = true;

        return $this;
    }

    /**
     * Establece que la columna use CURRENT_TIMESTAMP como default.
     */
    public function useCurrent(): self
    {
        $this->attributes['useCurrent'] = true;

        return $this;
    }

    /**
     * Establece que la columna se actualice con CURRENT_TIMESTAMP en UPDATE.
     */
    public function useCurrentOnUpdate(): self
    {
        $this->attributes['useCurrentOnUpdate'] = true;

        return $this;
    }

    /**
     * Marca la columna como que necesita ser modificada.
     * Esto se usa en ALTER TABLE para indicar que la columna debe ser cambiada.
     */
    public function change(): self
    {
        $this->attributes['change'] = true;

        return $this;
    }

    /**
     * Marca la columna como tipo ARRAY (PostgreSQL).
     */
    public function array(): self
    {
        $this->attributes['array'] = true;

        return $this;
    }

    /**
     * Crea una columna calculada almacenada.
     */
    public function storedAs(string $expression): self
    {
        $this->attributes['storedAs'] = $expression;

        return $this;
    }

    /**
     * Crea una columna calculada virtual.
     */
    public function virtualAs(string $expression): self
    {
        $this->attributes['virtualAs'] = $expression;

        return $this;
    }

    /**
     * Especifica la longitud para tipos que la soportan.
     */
    public function length(int $length): self
    {
        $this->attributes['length'] = $length;

        return $this;
    }

    /**
     * Especifica la precisión para tipos decimales.
     */
    public function precision(int $precision, int $scale = 0): self
    {
        $this->attributes['precision'] = $precision;
        $this->attributes['scale'] = $scale;

        return $this;
    }

    /**
     * Especifica los valores para columnas ENUM.
     *
     * @param array<int, string> $values
     */
    public function values(array $values): self
    {
        $this->attributes['values'] = $values;

        return $this;
    }

    /**
     * Crea una referencia de clave foránea.
     */
    public function references(string $column): ForeignKeyDefinition
    {
        $foreign = new ForeignKeyDefinition($this->name, $column);
        if ($this->blueprint !== null) {
            $this->blueprint->addForeignKey($foreign);
        }

        return $foreign;
    }

    /**
     * Crea una clave foránea usando convenciones.
     */
    public function constrained(?string $table = null, string $column = 'id', ?string $indexName = null): self
    {
        if ($table === null) {
            // Inferir nombre de tabla desde el nombre de columna
            $table = str_replace('_id', '', $this->name);
            $table = str_ends_with($table, 's') ? $table : $table . 's';
        }

        $foreign = new ForeignKeyDefinition($this->name, $column);
        $foreign->on($table);

        if ($indexName !== null) {
            $foreign->name($indexName);
        }

        if ($this->blueprint !== null) {
            $this->blueprint->addForeignKey($foreign);
        }

        // Guardar referencia a la foreign key para que métodos posteriores la puedan modificar
        $this->lastForeignKey = $foreign;

        return $this;
    }

    /**
     * Especifica acciones ON DELETE.
     */
    public function onDelete(string $action): self
    {
        $this->attributes['onDelete'] = strtoupper($action);

        // Si hay una foreign key asociada, actualizar también su acción onDelete
        if ($this->lastForeignKey !== null) {
            $this->lastForeignKey->onDelete($action);
        }

        return $this;
    }

    /**
     * Especifica acciones ON UPDATE.
     */
    public function onUpdate(string $action): self
    {
        $this->attributes['onUpdate'] = strtoupper($action);

        // Si hay una foreign key asociada, actualizar también su acción onUpdate
        if ($this->lastForeignKey !== null) {
            $this->lastForeignKey->onUpdate($action);
        }

        return $this;
    }

    /**
     * Acciones de cascada para DELETE.
     */
    public function cascadeOnDelete(): self
    {
        return $this->onDelete('CASCADE');
    }

    /**
     * Acciones de cascada para UPDATE.
     */
    public function cascadeOnUpdate(): self
    {
        return $this->onUpdate('CASCADE');
    }

    /**
     * Restricciones para DELETE.
     */
    public function restrictOnDelete(): self
    {
        return $this->onDelete('RESTRICT');
    }

    /**
     * Restricciones para UPDATE.
     */
    public function restrictOnUpdate(): self
    {
        return $this->onUpdate('RESTRICT');
    }

    /**
     * SET NULL para DELETE.
     */
    public function nullOnDelete(): self
    {
        return $this->onDelete('SET NULL');
    }

    /**
     * SET NULL para UPDATE.
     */
    public function nullOnUpdate(): self
    {
        return $this->onUpdate('SET NULL');
    }

    /**
     * Genera la definición SQL de la columna para el motor especificado.
     */
    public function toSql(string $driver): string
    {
        $sql = '';

        // Obtener el tipo SQL específico del motor
        $sqlType = TypeMapper::mapType($this->type, $driver, $this->attributes);

        if (is_array($sqlType)) {
            throw new \InvalidArgumentException("Column type {$this->type} returns multiple SQL types");
        }

        $wrappedName = $this->wrapColumn($this->name, $driver);
        $sql .= "{$wrappedName} {$sqlType}";

        // Aplicar modificadores específicos del motor
        $sql .= $this->buildModifiers($driver);

        return trim($sql);
    }

    /**
     * Envuelve un nombre de columna con los delimitadores apropiados según el motor.
     */
    protected function wrapColumn(string $column, string $driver): string
    {
        return match ($driver) {
            'mysql' => "`{$column}`",
            'postgresql' => "\"{$column}\"",
            'sqlite' => "\"{$column}\"",
            default => $column,
        };
    }

    /**
     * Construye los modificadores SQL específicos del motor.
     */
    protected function buildModifiers(string $driver): string
    {
        $modifiers = [];

        // NULL/NOT NULL
        if (isset($this->attributes['nullable'])) {
            $modifiers[] = (bool) $this->attributes['nullable'] ? 'NULL' : 'NOT NULL';
        } elseif ($this->getAttribute('primary', false) === false) {
            $modifiers[] = 'NOT NULL';
        }

        // DEFAULT
        if (isset($this->attributes['default'])) {
            $default = $this->attributes['default'];
            if (is_bool($default)) {
                $default = match ($driver) {
                    'mysql' => $default ? '1' : '0',
                    'postgresql' => $default ? 'TRUE' : 'FALSE',
                    'sqlite' => $default ? '1' : '0',
                    default => $default ? '1' : '0',
                };
            } elseif (is_string($default) && !in_array(strtoupper($default), ['CURRENT_TIMESTAMP', 'NOW()'], true)) {
                $default = "'{$default}'";
            } else {
                $default = is_scalar($default) ? (string) $default : '';
            }
            $modifiers[] = "DEFAULT {$default}";
        }

        // CURRENT_TIMESTAMP
        if ((bool) $this->getAttribute('useCurrent', false)) {
            $modifiers[] = 'DEFAULT CURRENT_TIMESTAMP';
        }

        // ON UPDATE CURRENT_TIMESTAMP (MySQL)
        if ((bool) $this->getAttribute('useCurrentOnUpdate', false) && $driver === 'mysql') {
            $modifiers[] = 'ON UPDATE CURRENT_TIMESTAMP';
        }

        // AUTO_INCREMENT (MySQL)
        if ((bool) $this->getAttribute('autoIncrement', false) && $driver === 'mysql') {
            $modifiers[] = 'AUTO_INCREMENT';
        }

        // COMMENT
        if (isset($this->attributes['comment'])) {
            $commentRaw = $this->attributes['comment'];
            $comment = str_replace("'", "''", is_scalar($commentRaw) ? (string) $commentRaw : '');
            $modifiers[] = "COMMENT '{$comment}'";
        }

        return $modifiers !== [] ? ' ' . implode(' ', $modifiers) : '';
    }
}

/**
 * Clase para definir claves foráneas de manera fluida.
 */
class ForeignKeyDefinition
{
    protected string $localColumn;

    protected string $foreignColumn;

    protected string $foreignTable = '';

    protected string $name = '';

    protected string $onDelete = '';

    protected string $onUpdate = '';

    public function __construct(string $localColumn, string $foreignColumn)
    {
        $this->localColumn = $localColumn;
        $this->foreignColumn = $foreignColumn;
    }

    /**
     * Especifica la tabla referenciada.
     */
    public function on(string $table): self
    {
        $this->foreignTable = $table;

        return $this;
    }

    /**
     * Especifica la columna referenciada.
     */
    public function references(string $column): self
    {
        $this->foreignColumn = $column;

        return $this;
    }

    /**
     * Especifica el nombre de la constraint.
     */
    public function name(string $name): self
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Especifica la acción ON DELETE.
     */
    public function onDelete(string $action): self
    {
        $this->onDelete = strtoupper($action);

        return $this;
    }

    /**
     * Especifica la acción ON UPDATE.
     */
    public function onUpdate(string $action): self
    {
        $this->onUpdate = strtoupper($action);

        return $this;
    }

    /**
     * Cascada en DELETE.
     */
    public function cascadeOnDelete(): self
    {
        return $this->onDelete('CASCADE');
    }

    /**
     * Cascada en UPDATE.
     */
    public function cascadeOnUpdate(): self
    {
        return $this->onUpdate('CASCADE');
    }

    /**
     * Getters para acceder a los valores.
     */
    public function getLocalColumn(): string
    {
        return $this->localColumn;
    }

    public function getForeignColumn(): string
    {
        return $this->foreignColumn;
    }

    public function getForeignTable(): string
    {
        return $this->foreignTable;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getOnDelete(): string
    {
        return $this->onDelete;
    }

    public function getOnUpdate(): string
    {
        return $this->onUpdate;
    }
}
