<?php

declare(strict_types=1);

namespace VersaORM\Schema;

use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * VersaSchema proporciona una fachada estática para el SchemaBuilder.
 *
 * Esta clase permite usar el SchemaBuilder de manera estática similar a Laravel,
 * facilitando las operaciones de esquema sin necesidad de instanciar manualmente
 * el SchemaBuilder.
 */
class VersaSchema
{
    protected static null|VersaORM $orm = null;

    protected static null|SchemaBuilder $schemaBuilder = null;

    /**
     * Establece la instancia ORM a usar para las operaciones de esquema.
     */
    public static function setORM(VersaORM $orm): void
    {
        static::$orm = $orm;
        static::$schemaBuilder = null; // Reset para forzar recreación
    }

    /**
     * Crea una nueva tabla usando una definición fluida.
     *
     * @param string $table Nombre de la tabla
     * @param callable $callback Función que recibe un Blueprint para definir la tabla
     * @param bool $ifNotExists Si incluir la cláusula IF NOT EXISTS
     */
    public static function create(string $table, callable $callback, bool $ifNotExists = false): void
    {
        static::getSchemaBuilder()->create($table, $callback, $ifNotExists);
    }

    /**
     * Modifica una tabla existente usando una definición fluida.
     *
     * @param string $table Nombre de la tabla
     * @param callable $callback Función que recibe un Blueprint para modificar la tabla
     */
    public static function table(string $table, callable $callback): void
    {
        static::getSchemaBuilder()->table($table, $callback);
    }

    /**
     * Renombra una tabla.
     */
    public static function rename(string $from, string $to): void
    {
        static::getSchemaBuilder()->rename($from, $to);
    }

    /**
     * Elimina una tabla.
     */
    public static function drop(string $table): void
    {
        static::getSchemaBuilder()->drop($table);
    }

    /**
     * Elimina una tabla si existe.
     */
    public static function dropIfExists(string $table): void
    {
        static::getSchemaBuilder()->dropIfExists($table);
    }

    /**
     * Verifica si una tabla existe.
     */
    public static function hasTable(string $table): bool
    {
        return static::getSchemaBuilder()->hasTable($table);
    }

    /**
     * Verifica si una columna existe en una tabla.
     */
    public static function hasColumn(string $table, string $column): bool
    {
        return static::getSchemaBuilder()->hasColumn($table, $column);
    }

    /**
     * Verifica si un índice existe en una tabla.
     *
     * @param array<int, string>|string $columns
     */
    public static function hasIndex(string $table, string|array $columns, string $type = 'index'): bool
    {
        return static::getSchemaBuilder()->hasIndex($table, $columns, $type);
    }

    /**
     * Obtiene la lista de columnas de una tabla.
     *
     * @return array<int, string>
     */
    public static function getColumnListing(string $table): array
    {
        return static::getSchemaBuilder()->getColumnListing($table);
    }

    /**
     * Obtiene información detallada de las columnas de una tabla.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getColumns(string $table): array
    {
        return static::getSchemaBuilder()->getColumns($table);
    }

    /**
     * Obtiene los índices de una tabla.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getIndexes(string $table): array
    {
        return static::getSchemaBuilder()->getIndexes($table);
    }

    /**
     * Obtiene las claves foráneas de una tabla.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getForeignKeys(string $table): array
    {
        return static::getSchemaBuilder()->getForeignKeys($table);
    }

    /**
     * Deshabilita las constraints de claves foráneas.
     */
    public static function disableForeignKeyConstraints(): void
    {
        static::getSchemaBuilder()->disableForeignKeyConstraints();
    }

    /**
     * Habilita las constraints de claves foráneas.
     */
    public static function enableForeignKeyConstraints(): void
    {
        static::getSchemaBuilder()->enableForeignKeyConstraints();
    }

    /**
     * Ejecuta una función sin constraints de claves foráneas.
     */
    public static function withoutForeignKeyConstraints(callable $callback): mixed
    {
        return static::getSchemaBuilder()->withoutForeignKeyConstraints($callback);
    }

    /**
     * Conecta a una base de datos específica para las operaciones de esquema.
     */
    public static function connection(string $name): static
    {
        // Esta funcionalidad se puede implementar más adelante si VersaORM soporta múltiples conexiones
        throw new \RuntimeException('Multiple database connections are not yet supported in VersaORM');
    }

    /**
     * Obtiene la instancia del SchemaBuilder.
     */
    protected static function getSchemaBuilder(): SchemaBuilder
    {
        if (static::$schemaBuilder === null) {
            if (static::$orm === null) {
                // Intentar obtener desde VersaModel si está configurado
                try {
                    static::$orm = VersaModel::getGlobalORM();
                    if (static::$orm === null) {
                        throw new \RuntimeException('No global ORM instance available');
                    }
                } catch (\Exception) {
                    throw new \RuntimeException('No VersaORM instance configured for VersaSchema. '
                    . 'Call VersaSchema::setORM() or configure VersaModel::setORM() first.');
                }
            }
            static::$schemaBuilder = new SchemaBuilder(static::$orm);
        }

        return static::$schemaBuilder;
    }
}
