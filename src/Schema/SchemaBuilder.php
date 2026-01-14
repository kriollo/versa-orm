<?php

declare(strict_types=1);

namespace VersaORM\Schema;

use VersaORM\VersaORM;
use VersaORM\VersaORMException;

/**
 * SchemaBuilder proporciona una API fluida moderna para manipular esquemas de base de datos.
 *
 * Esta clase es la fachada principal para todas las operaciones de schema, proporcionando
 * métodos fluidos similares a Laravel pero adaptados para VersaORM y con soporte
 * transparente para múltiples motores de base de datos.
 */
class SchemaBuilder
{
    protected VersaORM $orm;

    protected string $driver;

    public function __construct(VersaORM $orm)
    {
        $this->orm = $orm;
        $this->driver = $this->orm->getConfig()['driver'] ?? 'mysql';
    }

    /**
     * Crea una nueva tabla usando una definición fluida.
     *
     * @param string $table Nombre de la tabla
     * @param callable $callback Función que recibe un Blueprint para definir la tabla
     * @param bool $ifNotExists Si incluir la cláusula IF NOT EXISTS
     */
    public function create(string $table, callable $callback, bool $ifNotExists = false): void
    {
        $blueprint = new Blueprint($table);

        // Ejecutar el callback para definir la estructura
        $callback($blueprint);

        // Generar y ejecutar el SQL
        $sql = $this->buildCreateTableSql($blueprint, $ifNotExists);
        $this->orm->exec($sql);

        // Crear índices adicionales si los hay
        $this->createIndexes($blueprint);

        // Crear claves foráneas si las hay (solo para MySQL y PostgreSQL)
        if ($this->driver !== 'sqlite') {
            $this->createForeignKeys($blueprint);
        }
    }

    /**
     * Modifica una tabla existente usando una definición fluida.
     *
     * @param string $table Nombre de la tabla
     * @param callable $callback Función que recibe un Blueprint para modificar la tabla
     */
    public function table(string $table, callable $callback): void
    {
        $blueprint = new Blueprint($table);

        // Ejecutar el callback para definir los cambios
        $callback($blueprint);

        // Ejecutar comandos de modificación
        $this->executeCommands($blueprint);

        // Crear nuevas columnas si las hay
        $this->addNewColumns($blueprint);

        // Crear índices adicionales si los hay
        $this->createIndexes($blueprint);

        // Crear claves foráneas si las hay
        $this->createForeignKeys($blueprint);
    }

    /**
     * Renombra una tabla.
     */
    public function rename(string $from, string $to): void
    {
        $this->orm->schemaRename($from, $to);
    }

    /**
     * Elimina una tabla.
     */
    public function drop(string $table): void
    {
        $this->orm->schemaDrop($table, false);
    }

    /**
     * Elimina una tabla si existe.
     */
    public function dropIfExists(string $table): void
    {
        $this->orm->schemaDrop($table, true);
    }

    /**
     * Verifica si una tabla existe.
     */
    public function hasTable(string $table): bool
    {
        try {
            $result = $this->orm->schema('tables');
            $tables = is_array($result) ? $result : [];

            return in_array($table, array_column($tables, 'name'), true);
        } catch (\Exception) {
            return false;
        }
    }

    /**
     * Verifica si una columna existe en una tabla.
     */
    public function hasColumn(string $table, string $column): bool
    {
        try {
            $result = $this->orm->schema('columns', $table);
            $columns = is_array($result) ? $result : [];

            return in_array($column, array_column($columns, 'name'), true);
        } catch (\Exception) {
            return false;
        }
    }

    /**
     * Verifica si un índice existe en una tabla.
     *
     * @param array<int, string>|string $columns
     */
    public function hasIndex(string $table, string|array $columns, string $type = 'index'): bool
    {
        try {
            $result = $this->orm->schema('indexes', $table);
            $indexes = is_array($result) ? $result : [];

            $columnList = is_array($columns) ? $columns : [$columns];

            foreach ($indexes as $index) {
                if (!(isset($index['columns']) && $index['columns'] === $columnList)) {
                    continue;
                }

                if ($type === 'index' || isset($index['type']) && $index['type'] === $type) {
                    return true;
                }
            }

            return false;
        } catch (\Exception) {
            return false;
        }
    }

    /**
     * Obtiene la lista de columnas de una tabla.
     *
     * @return array<int, string>
     */
    public function getColumnListing(string $table): array
    {
        try {
            $result = $this->orm->schema('columns', $table);
            $columns = is_array($result) ? $result : [];

            return array_column($columns, 'name');
        } catch (\Exception) {
            return [];
        }
    }

    /**
     * Obtiene información detallada de las columnas de una tabla.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getColumns(string $table): array
    {
        try {
            $result = $this->orm->schema('columns', $table);

            return is_array($result) ? $result : [];
        } catch (\Exception) {
            return [];
        }
    }

    /**
     * Obtiene los índices de una tabla.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getIndexes(string $table): array
    {
        try {
            $result = $this->orm->schema('indexes', $table);

            return is_array($result) ? $result : [];
        } catch (\Exception) {
            return [];
        }
    }

    /**
     * Obtiene las claves foráneas de una tabla.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getForeignKeys(string $table): array
    {
        try {
            $result = $this->orm->schema('foreign_keys', $table);

            return is_array($result) ? $result : [];
        } catch (\Exception) {
            return [];
        }
    }

    /**
     * Deshabilita las constraints de claves foráneas.
     */
    public function disableForeignKeyConstraints(): void
    {
        switch ($this->driver) {
            case 'mysql':
                $this->orm->exec('SET FOREIGN_KEY_CHECKS=0');
                break;
            case 'postgresql':
                // PostgreSQL no tiene un equivalente global, se hace por tabla
                break;
            case 'sqlite':
                $this->orm->exec('PRAGMA foreign_keys = OFF');
                break;
        }
    }

    /**
     * Habilita las constraints de claves foráneas.
     */
    public function enableForeignKeyConstraints(): void
    {
        switch ($this->driver) {
            case 'mysql':
                $this->orm->exec('SET FOREIGN_KEY_CHECKS=1');
                break;
            case 'postgresql':
                // PostgreSQL no tiene un equivalente global
                break;
            case 'sqlite':
                $this->orm->exec('PRAGMA foreign_keys = ON');
                break;
        }
    }

    /**
     * Ejecuta una función sin constraints de claves foráneas.
     */
    public function withoutForeignKeyConstraints(callable $callback): mixed
    {
        $this->disableForeignKeyConstraints();

        try {
            return $callback();
        } finally {
            $this->enableForeignKeyConstraints();
        }
    }

    // Métodos internos

    /**
     * Construye el SQL para crear una tabla.
     */
    protected function buildCreateTableSql(Blueprint $blueprint, bool $ifNotExists = false): string
    {
        $table = $blueprint->getTable();
        $columns = $blueprint->getColumns();

        if ($columns === []) {
            throw new VersaORMException("No columns defined for table {$table}");
        }

        $sql = 'CREATE TABLE ';

        if ($ifNotExists) {
            $sql .= 'IF NOT EXISTS ';
        }

        $sql .= $this->wrapTable($table) . ' (';

        // Construir definiciones de columnas
        $columnDefinitions = [];
        foreach ($columns as $column) {
            $columnDefinitions[] = $column->toSql($this->driver);
        }

        $sql .= implode(', ', $columnDefinitions);

        // Añadir índices de tabla (PRIMARY KEY, etc.)
        $tableIndexes = $this->buildTableIndexes($blueprint);
        if ($tableIndexes !== []) {
            $sql .= ', ' . implode(', ', $tableIndexes);
        }

        $sql .= ')';

        // Añadir opciones específicas del motor
        $sql .= $this->buildTableOptions($blueprint);

        return $sql;
    }

    /**
     * Construye los índices a nivel de tabla.
     *
     * @return array<int, string>
     */
    protected function buildTableIndexes(Blueprint $blueprint): array
    {
        $indexes = [];

        foreach ($blueprint->getIndexes() as $index) {
            $type = $index['type'];
            $columns = $index['columns'];
            $name = $index['name'];

            switch ($type) {
                case 'primary':
                    $indexes[] = 'PRIMARY KEY (' . implode(', ', array_map([$this, 'wrapColumn'], $columns)) . ')';
                    break;
                case 'unique':
                    $constraintName = $name !== null && $name !== '' ? "CONSTRAINT {$this->wrapColumn($name)} " : '';
                    $indexes[] =
                        $constraintName . 'UNIQUE (' . implode(', ', array_map([$this, 'wrapColumn'], $columns)) . ')';
                    break;

                // Los índices regulares se crean por separado
            }
        }

        // Para SQLite, añadir foreign keys a nivel de tabla
        if ($this->driver === 'sqlite') {
            foreach ($blueprint->getForeignKeys() as $foreign) {
                $localColumn = $foreign->getLocalColumn();
                $foreignTable = $foreign->getForeignTable();
                $foreignColumn = $foreign->getForeignColumn();

                $foreignKeyDef =
                    "FOREIGN KEY ({$this->wrapColumn($localColumn)}) "
                    . "REFERENCES {$this->wrapTable($foreignTable)} ({$this->wrapColumn($foreignColumn)})";

                if ($foreign->getOnDelete() !== '') {
                    $foreignKeyDef .= " ON DELETE {$foreign->getOnDelete()}";
                }

                if ($foreign->getOnUpdate() !== '') {
                    $foreignKeyDef .= " ON UPDATE {$foreign->getOnUpdate()}";
                }

                $indexes[] = $foreignKeyDef;
            }
        }

        return $indexes;
    }

    /**
     * Construye las opciones específicas de la tabla según el motor.
     */
    protected function buildTableOptions(Blueprint $blueprint): string
    {
        $options = [];

        switch ($this->driver) {
            case 'mysql':
                if ($blueprint->getEngine() !== '') {
                    $options[] = 'ENGINE=' . $blueprint->getEngine();
                }
                if ($blueprint->getCharset() !== '') {
                    $options[] = 'DEFAULT CHARSET=' . $blueprint->getCharset();
                }
                if ($blueprint->getCollation() !== '') {
                    $options[] = 'COLLATE=' . $blueprint->getCollation();
                }
                if ($blueprint->getComment() !== '') {
                    $options[] = "COMMENT='" . str_replace("'", "''", $blueprint->getComment()) . "'";
                }
                break;

            case 'postgresql':
                // PostgreSQL no tiene opciones equivalentes en CREATE TABLE
                break;

            case 'sqlite':
                // SQLite no tiene opciones equivalentes
                break;
        }

        return $options !== [] ? ' ' . implode(' ', $options) : '';
    }

    /**
     * Crea los índices definidos en el blueprint.
     */
    protected function createIndexes(Blueprint $blueprint): void
    {
        foreach ($blueprint->getIndexes() as $index) {
            if (in_array($index['type'], ['primary', 'unique'], true)) {
                continue; // Ya se crearon a nivel de tabla
            }

            $this->createIndex($blueprint->getTable(), $index);
        }
    }

    /**
     * Crea un índice individual.
     *
     * @param array<string, mixed> $index
     */
    protected function createIndex(string $table, array $index): void
    {
        $type = $index['type'];
        $columns = $index['columns'];
        $name = $index['name'] ?? $this->generateIndexName($table, $columns, $type);

        $sql = match ($type) {
            'index' => "CREATE INDEX {$this->wrapColumn($name)} ON {$this->wrapTable($table)} ("
                . implode(', ', array_map([$this, 'wrapColumn'], $columns))
                . ')',
            'unique' => "CREATE UNIQUE INDEX {$this->wrapColumn($name)} ON {$this->wrapTable($table)} ("
                . implode(', ', array_map([$this, 'wrapColumn'], $columns))
                . ')',
            'fulltext' => $this->buildFullTextIndex($table, $columns, $name),
            'spatial' => $this->buildSpatialIndex($table, $columns, $name),
            default => throw new VersaORMException("Unsupported index type: {$type}"),
        };

        $this->orm->exec($sql);
    }

    /**
     * Construye un índice de texto completo.
     *
     * @param array<int, string> $columns
     */
    protected function buildFullTextIndex(string $table, array $columns, string $name): string
    {
        return match ($this->driver) {
            'mysql' => "CREATE FULLTEXT INDEX {$this->wrapColumn($name)} ON {$this->wrapTable($table)} ("
                . implode(', ', array_map([$this, 'wrapColumn'], $columns))
                . ')',
            'postgresql' => "CREATE INDEX {$this->wrapColumn($name)} ON {$this->wrapTable(
     $table,
 )} USING gin(to_tsvector('english', "
                . implode(" || ' ' || ", array_map([$this, 'wrapColumn'], $columns))
                . '))',
            default => throw new VersaORMException("Full-text indexes are not supported for {$this->driver}"),
        };
    }

    /**
     * Construye un índice espacial.
     *
     * @param array<int, string> $columns
     */
    protected function buildSpatialIndex(string $table, array $columns, string $name): string
    {
        return match ($this->driver) {
            'mysql' => "CREATE SPATIAL INDEX {$this->wrapColumn($name)} ON {$this->wrapTable($table)} ("
                . implode(', ', array_map([$this, 'wrapColumn'], $columns))
                . ')',
            'postgresql' => "CREATE INDEX {$this->wrapColumn($name)} ON {$this->wrapTable($table)} USING gist ("
                . implode(', ', array_map([$this, 'wrapColumn'], $columns))
                . ')',
            default => throw new VersaORMException("Spatial indexes are not supported for {$this->driver}"),
        };
    }

    /**
     * Crea las claves foráneas definidas en el blueprint.
     */
    protected function createForeignKeys(Blueprint $blueprint): void
    {
        foreach ($blueprint->getForeignKeys() as $foreign) {
            $this->createForeignKey($blueprint->getTable(), $foreign);
        }
    }

    /**
     * Crea una clave foránea individual.
     */
    protected function createForeignKey(string $table, ForeignKeyDefinition $foreign): void
    {
        // SQLite no soporta ALTER TABLE ADD CONSTRAINT para foreign keys
        // Las foreign keys deben definirse al crear la tabla
        if ($this->driver === 'sqlite') {
            // Para SQLite, registramos que se necesita recrear la tabla
            // Por ahora, saltamos la creación de foreign keys para SQLite
            return;
        }

        $localColumn = $foreign->getLocalColumn();
        $foreignTable = $foreign->getForeignTable();
        $foreignColumn = $foreign->getForeignColumn();
        $name = $foreign->getName() !== '' ? $foreign->getName() : $this->generateForeignKeyName($table, $localColumn);

        $sql =
            "ALTER TABLE {$this->wrapTable($table)} ADD CONSTRAINT {$this->wrapColumn($name)} "
            . "FOREIGN KEY ({$this->wrapColumn($localColumn)}) "
            . "REFERENCES {$this->wrapTable($foreignTable)} ({$this->wrapColumn($foreignColumn)})";

        if ($foreign->getOnDelete() !== '') {
            $sql .= " ON DELETE {$foreign->getOnDelete()}";
        }

        if ($foreign->getOnUpdate() !== '') {
            $sql .= " ON UPDATE {$foreign->getOnUpdate()}";
        }

        $this->orm->exec($sql);
    }

    /**
     * Ejecuta los comandos definidos en el blueprint.
     */
    protected function executeCommands(Blueprint $blueprint): void
    {
        foreach ($blueprint->getCommands() as $command) {
            $this->executeCommand($blueprint->getTable(), $command);
        }
    }

    /**
     * Ejecuta un comando individual.
     *
     * @param array<string, mixed> $command
     */
    protected function executeCommand(string $table, array $command): void
    {
        $name = $command['name'];

        switch ($name) {
            case 'dropColumn':
                $this->dropColumns($table, $command['columns']);
                break;
            case 'renameColumn':
                $this->renameColumn($table, $command['from'], $command['to']);
                break;
            case 'dropIndex':
                $this->dropIndex($table, $command['index']);
                break;
            case 'dropUnique':
                $this->dropIndex($table, $command['index'], 'unique');
                break;
            case 'dropPrimary':
                $this->dropPrimaryKey($table);
                break;
            case 'dropForeign':
                $this->dropForeignKey($table, $command['index']);
                break;
            case 'renameIndex':
                $this->renameIndex($table, $command['from'], $command['to']);
                break;
        }
    }

    /**
     * Añade nuevas columnas a una tabla existente.
     */
    protected function addNewColumns(Blueprint $blueprint): void
    {
        foreach ($blueprint->getColumns() as $column) {
            $sql = "ALTER TABLE {$this->wrapTable($blueprint->getTable())} ADD COLUMN " . $column->toSql($this->driver);
            $this->orm->exec($sql);
        }
    }

    /**
     * Elimina columnas de una tabla.
     *
     * @param array<int, string> $columns
     */
    protected function dropColumns(string $table, array $columns): void
    {
        foreach ($columns as $column) {
            $sql = "ALTER TABLE {$this->wrapTable($table)} DROP COLUMN {$this->wrapColumn($column)}";
            $this->orm->exec($sql);
        }
    }

    /**
     * Renombra una columna.
     */
    protected function renameColumn(string $table, string $from, string $to): void
    {
        $sql = match ($this->driver) {
            'mysql' => "ALTER TABLE {$this->wrapTable($table)} RENAME COLUMN {$this->wrapColumn(
     $from,
 )} TO {$this->wrapColumn($to)}",
            'postgresql' => "ALTER TABLE {$this->wrapTable($table)} RENAME COLUMN {$this->wrapColumn(
     $from,
 )} TO {$this->wrapColumn($to)}",
            'sqlite' => throw new VersaORMException('SQLite does not support renaming columns'),
            default => throw new VersaORMException("Unsupported driver: {$this->driver}"),
        };

        $this->orm->exec($sql);
    }

    /**
     * Elimina un índice.
     *
     * @param array<int, string>|string $index
     */
    protected function dropIndex(string $table, string|array $index, string $type = 'index'): void
    {
        $indexName = is_array($index) ? $this->generateIndexName($table, $index, $type) : $index;

        $sql = match ($this->driver) {
            'mysql' => "ALTER TABLE {$this->wrapTable($table)} DROP INDEX {$this->wrapColumn($indexName)}",
            'postgresql' => "DROP INDEX {$this->wrapColumn($indexName)}",
            'sqlite' => "DROP INDEX {$this->wrapColumn($indexName)}",
            default => throw new VersaORMException("Unsupported driver: {$this->driver}"),
        };

        $this->orm->exec($sql);
    }

    /**
     * Elimina la clave primaria.
     */
    protected function dropPrimaryKey(string $table): void
    {
        $sql = match ($this->driver) {
            'mysql' => "ALTER TABLE {$this->wrapTable($table)} DROP PRIMARY KEY",
            'postgresql' => "ALTER TABLE {$this->wrapTable($table)} DROP CONSTRAINT {$this->wrapColumn($table
 . '_pkey')}",
            'sqlite' => throw new VersaORMException('SQLite does not support dropping primary keys'),
            default => throw new VersaORMException("Unsupported driver: {$this->driver}"),
        };

        $this->orm->exec($sql);
    }

    /**
     * Elimina una clave foránea.
     *
     * @param array<int, string>|string $key
     */
    protected function dropForeignKey(string $table, string|array $key): void
    {
        $keyName = is_array($key) ? $this->generateForeignKeyName($table, $key[0]) : $key;

        $sql = "ALTER TABLE {$this->wrapTable($table)} DROP FOREIGN KEY {$this->wrapColumn($keyName)}";
        $this->orm->exec($sql);
    }

    /**
     * Renombra un índice.
     */
    protected function renameIndex(string $table, string $from, string $to): void
    {
        $sql = match ($this->driver) {
            'mysql' => "ALTER TABLE {$this->wrapTable($table)} RENAME INDEX {$this->wrapColumn(
     $from,
 )} TO {$this->wrapColumn($to)}",
            'postgresql' => "ALTER INDEX {$this->wrapColumn($from)} RENAME TO {$this->wrapColumn($to)}",
            'sqlite' => throw new VersaORMException('SQLite does not support renaming indexes'),
            default => throw new VersaORMException("Unsupported driver: {$this->driver}"),
        };

        $this->orm->exec($sql);
    }

    // Métodos de utilidad

    /**
     * Envuelve un nombre de tabla con los delimitadores apropiados.
     */
    protected function wrapTable(string $table): string
    {
        return match ($this->driver) {
            'mysql' => "`{$table}`",
            'postgresql' => "\"{$table}\"",
            'sqlite' => "\"{$table}\"",
            default => $table,
        };
    }

    /**
     * Envuelve un nombre de columna con los delimitadores apropiados.
     */
    protected function wrapColumn(string $column): string
    {
        return match ($this->driver) {
            'mysql' => "`{$column}`",
            'postgresql' => "\"{$column}\"",
            'sqlite' => "\"{$column}\"",
            default => $column,
        };
    }

    /**
     * Genera un nombre de índice automático.
     *
     * @param array<int, string> $columns
     */
    protected function generateIndexName(string $table, array $columns, string $type): string
    {
        $suffix = match ($type) {
            'primary' => 'primary',
            'unique' => 'unique',
            'index' => 'index',
            'fulltext' => 'fulltext',
            'spatial' => 'spatial',
            default => 'index',
        };

        return $table . '_' . implode('_', $columns) . '_' . $suffix;
    }

    /**
     * Genera un nombre de clave foránea automático.
     */
    protected function generateForeignKeyName(string $table, string $column): string
    {
        return $table . '_' . $column . '_foreign';
    }
}
