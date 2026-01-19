<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

final class VersaORMSchemaOperationsTest extends TestCase
{
    public function test_schema_create_rename_drop_and_columns()
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);

        $cols = [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'name', 'type' => 'TEXT', 'nullable' => false],
        ];

        $options = ['indexes' => [['name' => 'idx_name', 'columns' => ['name']]]];

        $orm->schemaCreate('test_table', $cols, $options);

        $tables = $orm->schema('tables');
        static::assertContains('test_table', $tables);

        $columns = $orm->schema('columns', 'test_table');
        $names = array_map(static fn($c) => $c['name'] ?? $c['column_name'] ?? null, $columns);

        static::assertContains('id', $names);
        static::assertContains('name', $names);

        // rename
        $orm->schemaRename('test_table', 'test_table_renamed');
        static::assertContains('test_table_renamed', $orm->schema('tables'));

        // drop
        $orm->schemaDrop('test_table_renamed');
        static::assertNotContains('test_table_renamed', $orm->schema('tables'));
    }
}
