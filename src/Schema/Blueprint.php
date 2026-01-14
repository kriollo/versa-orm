<?php

declare(strict_types=1);

namespace VersaORM\Schema;

/**
 * Blueprint representa la definición de una tabla durante una operación de schema.
 *
 * Esta clase proporciona una API fluida para definir la estructura de una tabla,
 * incluyendo columnas, índices, claves foráneas y otras constraints.
 */
class Blueprint
{
    protected string $table;

    /** @var array<int, ColumnDefinition> */
    protected array $columns = [];

    /** @var array<int, array<string, mixed>> */
    protected array $indexes = [];

    /** @var array<int, ForeignKeyDefinition> */
    protected array $foreignKeys = [];

    /** @var array<int, array<string, mixed>> */
    protected array $commands = [];

    protected bool $temporary = false;

    protected string $engine = '';

    protected string $charset = '';

    protected string $collation = '';

    protected string $comment = '';

    public function __construct(string $table)
    {
        $this->table = $table;
    }

    /**
     * Obtiene el nombre de la tabla.
     */
    public function getTable(): string
    {
        return $this->table;
    }

    /**
     * Obtiene todas las columnas definidas.
     *
     * @return array<int, ColumnDefinition>
     */
    public function getColumns(): array
    {
        return $this->columns;
    }

    /**
     * Obtiene todos los índices definidos.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getIndexes(): array
    {
        return $this->indexes;
    }

    /**
     * Obtiene todas las claves foráneas definidas.
     *
     * @return array<int, ForeignKeyDefinition>
     */
    public function getForeignKeys(): array
    {
        return $this->foreignKeys;
    }

    /**
     * Obtiene todos los comandos pendientes.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getCommands(): array
    {
        return $this->commands;
    }

    // Métodos para definir columnas

    /**
     * Crea una columna de tipo auto-incrementing BIGINT (clave primaria).
     */
    public function id(string $column = 'id'): ColumnDefinition
    {
        return $this->addColumn($column, 'id')->primary()->autoIncrement();
    }

    /**
     * Crea una columna de tipo auto-incrementing INT.
     */
    public function increments(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'increments')->primary()->autoIncrement();
    }

    /**
     * Crea una columna de tipo auto-incrementing BIGINT.
     */
    public function bigIncrements(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'bigIncrements')->primary()->autoIncrement();
    }

    /**
     * Crea una columna de tipo VARCHAR.
     */
    public function string(string $column, int $length = 255): ColumnDefinition
    {
        return $this->addColumn($column, 'string')->length($length);
    }

    /**
     * Crea una columna de tipo TEXT.
     */
    public function text(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'text');
    }

    /**
     * Crea una columna de tipo MEDIUMTEXT.
     */
    public function mediumText(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'mediumText');
    }

    /**
     * Crea una columna de tipo LONGTEXT.
     */
    public function longText(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'longText');
    }

    /**
     * Crea una columna de tipo INTEGER.
     */
    public function integer(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'integer');
    }

    /**
     * Crea una columna de tipo BIGINT.
     */
    public function bigInteger(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'bigInteger');
    }

    /**
     * Crea una columna de tipo MEDIUMINT.
     */
    public function mediumInteger(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'mediumInteger');
    }

    /**
     * Crea una columna de tipo SMALLINT.
     */
    public function smallInteger(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'smallInteger');
    }

    /**
     * Crea una columna de tipo TINYINT.
     */
    public function tinyInteger(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'tinyInteger');
    }

    /**
     * Crea una columna de tipo UNSIGNED INTEGER.
     */
    public function unsignedInteger(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'unsignedInteger');
    }

    /**
     * Crea una columna de tipo UNSIGNED BIGINT.
     */
    public function unsignedBigInteger(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'unsignedBigInteger');
    }

    /**
     * Crea una columna de tipo FLOAT.
     */
    public function float(string $column, int $precision = 8, int $scale = 2): ColumnDefinition
    {
        return $this->addColumn($column, 'float')->precision($precision, $scale);
    }

    /**
     * Crea una columna de tipo DOUBLE.
     */
    public function double(string $column, int $precision = 15, int $scale = 8): ColumnDefinition
    {
        return $this->addColumn($column, 'double')->precision($precision, $scale);
    }

    /**
     * Crea una columna de tipo DECIMAL.
     */
    public function decimal(string $column, int $precision = 8, int $scale = 2): ColumnDefinition
    {
        return $this->addColumn($column, 'decimal')->precision($precision, $scale);
    }

    /**
     * Crea una columna de tipo BOOLEAN.
     */
    public function boolean(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'boolean');
    }

    /**
     * Crea una columna de tipo ENUM.
     *
     * @param array<int, string> $values
     */
    public function enum(string $column, array $values): ColumnDefinition
    {
        return $this->addColumn($column, 'enum')->values($values);
    }

    /**
     * Crea una columna de tipo SET (MySQL).
     *
     * @param array<int, string> $values
     */
    public function set(string $column, array $values): ColumnDefinition
    {
        return $this->addColumn($column, 'set')->values($values);
    }

    /**
     * Crea una columna de tipo JSON.
     */
    public function json(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'json');
    }

    /**
     * Crea una columna de tipo DATE.
     */
    public function date(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'date');
    }

    /**
     * Crea una columna de tipo DATETIME.
     */
    public function dateTime(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'dateTime');
    }

    /**
     * Crea una columna de tipo TIME.
     */
    public function time(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'time');
    }

    /**
     * Crea una columna de tipo TIMESTAMP.
     */
    public function timestamp(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'timestamp');
    }

    /**
     * Crea columnas created_at y updated_at de tipo TIMESTAMP.
     */
    public function timestamps(): void
    {
        $this->timestamp('created_at')->nullable()->useCurrent();
        $this
            ->timestamp('updated_at')
            ->nullable()
            ->useCurrent()
            ->useCurrentOnUpdate();
    }

    /**
     * Crea una columna de tipo BINARY.
     */
    public function binary(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'binary');
    }

    /**
     * Crea una columna de tipo UUID.
     */
    public function uuid(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'uuid');
    }

    /**
     * Crea una columna de tipo CHAR.
     */
    public function char(string $column, int $length = 255): ColumnDefinition
    {
        return $this->addColumn($column, 'char')->length($length);
    }

    /**
     * Crea una columna para dirección IP.
     */
    public function ipAddress(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'ipAddress');
    }

    /**
     * Crea una columna para dirección MAC.
     */
    public function macAddress(string $column): ColumnDefinition
    {
        return $this->addColumn($column, 'macAddress');
    }

    /**
     * Crea una columna remember_token para autenticación.
     */
    public function rememberToken(): ColumnDefinition
    {
        return $this->string('remember_token', 100)->nullable();
    }

    /**
     * Crea columnas para relaciones polimórficas.
     */
    public function morphs(string $name): void
    {
        $this->unsignedBigInteger($name . '_id');
        $this->string($name . '_type');
    }

    /**
     * Crea columnas para relaciones polimórficas nullable.
     */
    public function nullableMorphs(string $name): void
    {
        $this->unsignedBigInteger($name . '_id')->nullable();
        $this->string($name . '_type')->nullable();
    }

    /**
     * Crea una columna foreign ID.
     */
    public function foreignId(string $column): ColumnDefinition
    {
        return $this->unsignedBigInteger($column);
    }

    /**
     * Crea una columna foreign ID basada en un modelo.
     */
    public function foreignIdFor(string $model, string $column = null): ColumnDefinition
    {
        if ($column === null) {
            $baseName = basename(str_replace('\\', '/', $model));
            $column = strtolower($baseName) . '_id';
        }

        return $this->foreignId($column);
    }

    // Métodos para modificar columnas existentes

    /**
     * Modifica una columna existente.
     */
    public function change(): void
    {
        $this->addCommand('change');
    }

    /**
     * Renombra una columna.
     */
    public function renameColumn(string $from, string $to): void
    {
        $this->addCommand('renameColumn', compact('from', 'to'));
    }

    /**
     * Elimina una columna.
     *
     * @param array<int, string>|string $columns
     */
    public function dropColumn(string|array $columns): void
    {
        $columns = is_array($columns) ? $columns : func_get_args();
        $this->addCommand('dropColumn', compact('columns'));
    }

    // Métodos para índices

    /**
     * Crea una clave primaria.
     *
     * @param array<int, string>|string $columns
     */
    public function primary(string|array $columns, string $name = null): void
    {
        $this->addIndex('primary', $columns, $name);
    }

    /**
     * Crea un índice único.
     *
     * @param array<int, string>|string $columns
     */
    public function unique(string|array $columns, string $name = null): void
    {
        $this->addIndex('unique', $columns, $name);
    }

    /**
     * Crea un índice regular.
     *
     * @param array<int, string>|string $columns
     */
    public function index(string|array $columns, string $name = null): void
    {
        $this->addIndex('index', $columns, $name);
    }

    /**
     * Crea un índice de texto completo.
     *
     * @param array<int, string>|string $columns
     */
    public function fullText(string|array $columns, string $name = null): void
    {
        $this->addIndex('fulltext', $columns, $name);
    }

    /**
     * Crea un índice espacial.
     *
     * @param array<int, string>|string $columns
     */
    public function spatialIndex(string|array $columns, string $name = null): void
    {
        $this->addIndex('spatial', $columns, $name);
    }

    /**
     * Elimina una clave primaria.
     */
    public function dropPrimary(string $index = null): void
    {
        $this->addCommand('dropPrimary', compact('index'));
    }

    /**
     * Elimina un índice único.
     *
     * @param array<int, string>|string $index
     */
    public function dropUnique(string|array $index): void
    {
        $this->addCommand('dropUnique', compact('index'));
    }

    /**
     * Elimina un índice regular.
     *
     * @param array<int, string>|string $index
     */
    public function dropIndex(string|array $index): void
    {
        $this->addCommand('dropIndex', compact('index'));
    }

    /**
     * Renombra un índice.
     */
    public function renameIndex(string $from, string $to): void
    {
        $this->addCommand('renameIndex', compact('from', 'to'));
    }

    // Métodos para claves foráneas

    /**
     * Crea una clave foránea.
     *
     * @param array<int, string>|string $columns
     */
    public function foreign(string|array $columns, string $name = null): ForeignKeyDefinition
    {
        $columns = is_array($columns) ? $columns : [$columns];
        $foreign = new ForeignKeyDefinition($columns[0], '');

        if ($name !== null) {
            $foreign->name($name);
        }

        $this->addForeignKey($foreign);

        return $foreign;
    }

    /**
     * Elimina una clave foránea.
     *
     * @param array<int, string>|string $index
     */
    public function dropForeign(string|array $index): void
    {
        $this->addCommand('dropForeign', compact('index'));
    }

    // Métodos para configuración de tabla

    /**
     * Especifica que la tabla debe ser temporal.
     */
    public function temporary(): self
    {
        $this->temporary = true;

        return $this;
    }

    /**
     * Especifica el motor de almacenamiento (MySQL).
     */
    public function engine(string $engine): self
    {
        $this->engine = $engine;

        return $this;
    }

    /**
     * Especifica el charset de la tabla (MySQL).
     */
    public function charset(string $charset): self
    {
        $this->charset = $charset;

        return $this;
    }

    /**
     * Especifica la collation de la tabla (MySQL).
     */
    public function collation(string $collation): self
    {
        $this->collation = $collation;

        return $this;
    }

    /**
     * Añade un comentario a la tabla.
     */
    public function comment(string $comment): self
    {
        $this->comment = $comment;

        return $this;
    }

    /**
     * Añade un índice.
     *
     * @param array<int, string>|string $columns
     */
    public function addIndex(string $type, string|array $columns, string $name = null): void
    {
        $columns = is_array($columns) ? $columns : [$columns];

        $this->indexes[] = [
            'type' => $type,
            'columns' => $columns,
            'name' => $name,
        ];
    }

    /**
     * Añade una clave foránea.
     */
    public function addForeignKey(ForeignKeyDefinition $foreign): void
    {
        $this->foreignKeys[] = $foreign;
    }

    /**
     * Verifica si la tabla es temporal.
     */
    public function isTemporary(): bool
    {
        return $this->temporary;
    }

    /**
     * Obtiene el motor de almacenamiento.
     */
    public function getEngine(): string
    {
        return $this->engine;
    }

    /**
     * Obtiene el charset.
     */
    public function getCharset(): string
    {
        return $this->charset;
    }

    /**
     * Obtiene la collation.
     */
    public function getCollation(): string
    {
        return $this->collation;
    }

    /**
     * Obtiene el comentario de la tabla.
     */
    public function getComment(): string
    {
        return $this->comment;
    }

    // Métodos internos

    /**
     * Añade una nueva columna.
     */
    protected function addColumn(string $name, string $type): ColumnDefinition
    {
        $column = new ColumnDefinition($name, $type, $this);
        $this->columns[] = $column;

        return $column;
    }

    /**
     * Añade un comando a la lista de comandos pendientes.
     *
     * @param array<string, mixed> $parameters
     */
    protected function addCommand(string $name, array $parameters = []): void
    {
        $this->commands[] = array_merge(['name' => $name], $parameters);
    }
}
