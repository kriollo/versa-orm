<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * @group mysql
 */
final class SchemaAllMysqlTest extends TestCase
{
    public function test_schema_create_generates_valid_sql(): void
    {
        $orm = $this->makeOrmCollector();

        $columns = [
            ['name' => 'id', 'type' => 'INT', 'nullable' => false, 'primary' => true, 'autoIncrement' => true],
            ['name' => 'name', 'type' => 'VARCHAR(50)', 'nullable' => false],
        ];

        $options = [
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'indexes' => [
                ['name' => 'idx_name', 'columns' => ['name'], 'unique' => false, 'using' => 'BTREE'],
            ],
            'if_not_exists' => true,
        ];

        $orm->schemaCreate('test_schema_all', $columns, $options);

        $captured = $orm->captured;
        self::assertNotEmpty($captured);

        $foundCreate = false;
        $foundIndex = false;
        foreach ($captured as $sql) {
            $u = strtoupper($sql);
            if (str_contains($u, 'CREATE TABLE')) {
                $foundCreate = true;
            }
            if (str_contains($u, 'CREATE INDEX') || str_contains($u, 'CREATE UNIQUE INDEX')) {
                $foundIndex = true;
            }
        }

        self::assertTrue($foundCreate, 'CREATE TABLE not generated');
        self::assertTrue($foundIndex, 'CREATE INDEX not generated');
    }

    public function test_schema_alter_add_and_drop_columns_indexes_foreign(): void
    {
        $orm = $this->makeOrmCollector();

        // add columns
        $orm->schemaAlter('test_schema_all', [
            'add' => [
                ['name' => 'age', 'type' => 'INT', 'nullable' => true],
            ],
        ]);

        // add index
        $orm->schemaAlter('test_schema_all', [
            'addIndex' => [
                ['name' => 'idx_age', 'columns' => ['age'], 'unique' => false, 'using' => 'BTREE'],
            ],
        ]);

        // add foreign
        $orm->schemaAlter('test_schema_all', [
            'addForeign' => [
                [
                    'name' => 'fk_test_other',
                    'columns' => ['age'],
                    'refTable' => 'other',
                    'refColumns' => ['id'],
                    'onDelete' => 'cascade',
                ],
            ],
        ]);

        // drop foreign
        $orm->schemaAlter('test_schema_all', [
            'dropForeign' => ['fk_test_other'],
        ]);

        // drop index
        $orm->schemaAlter('test_schema_all', [
            'dropIndex' => ['idx_age'],
        ]);

        // drop column
        $orm->schemaAlter('test_schema_all', [
            'drop' => [['name' => 'age']],
        ]);

        $captured = $orm->captured;
        self::assertNotEmpty($captured);

        $hasAddColumn = false;
        $hasAddIndex = false;
        $hasAddForeign = false;
        $hasDropForeign = false;
        $hasDropIndex = false;
        $hasDropColumn = false;

        foreach ($captured as $sql) {
            $u = strtoupper($sql);
            if (str_contains($u, 'ADD COLUMN')) {
                $hasAddColumn = true;
            }
            if (str_contains($u, 'ADD CONSTRAINT') || str_contains($u, 'ADD INDEX')) {
                $hasAddForeign = true;
                $hasAddIndex = true;
            }
            if (str_contains($u, 'DROP FOREIGN KEY') || str_contains($u, 'DROP CONSTRAINT')) {
                $hasDropForeign = true;
            }
            if (str_contains($u, 'DROP INDEX') || str_contains($u, 'DROP KEY')) {
                $hasDropIndex = true;
            }
            if (str_contains($u, 'DROP COLUMN')) {
                $hasDropColumn = true;
            }
        }

        self::assertTrue($hasAddColumn, 'ADD COLUMN missing');
        self::assertTrue($hasAddIndex, 'ADD INDEX missing');
        self::assertTrue($hasAddForeign, 'ADD FOREIGN missing');
        self::assertTrue($hasDropForeign, 'DROP FOREIGN missing');
        self::assertTrue($hasDropIndex, 'DROP INDEX missing');
        self::assertTrue($hasDropColumn, 'DROP COLUMN missing');
    }

    public function test_schema_rename_and_drop_table(): void
    {
        $orm = $this->makeOrmCollector();

        $orm->schemaRename('old_table_name', 'new_table_name');
        $orm->schemaDrop('new_table_name', true);

        $captured = $orm->captured;
        self::assertNotEmpty($captured);

        $hasRename = false;
        $hasDrop = false;
        foreach ($captured as $sql) {
            $u = strtoupper($sql);
            if (str_contains($u, 'RENAME TABLE') || str_contains($u, 'ALTER TABLE')) {
                $hasRename = true;
            }
            if (str_contains($u, 'DROP TABLE')) {
                $hasDrop = true;
            }
        }

        self::assertTrue($hasRename, 'RENAME not executed');
        self::assertTrue($hasDrop, 'DROP TABLE not executed');
    }

    private function makeOrmCollector(): object
    {
        return new class() extends VersaORM {
            public array $captured = [];

            public function __construct()
            {
                parent::__construct(['driver' => 'mysql']);
            }

            public function exec(string $query, array $bindings = [])
            {
                $this->captured[] = $query;

                return null;
            }
        };
    }
}
