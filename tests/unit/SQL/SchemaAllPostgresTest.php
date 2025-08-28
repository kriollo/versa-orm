<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * @group postgresql
 */
final class SchemaAllPostgresTest extends TestCase
{
    public function test_schema_create_generates_valid_sql(): void
    {
        $orm = $this->makeOrmCollector();

        $columns = [
            ['name' => 'id', 'type' => 'INT', 'nullable' => false, 'primary' => true, 'autoIncrement' => true],
            ['name' => 'name', 'type' => 'VARCHAR(50)', 'nullable' => false],
        ];

        $options = [
            'indexes' => [
                ['name' => 'idx_name', 'columns' => ['name'], 'unique' => false, 'using' => 'BTREE'],
            ],
            'if_not_exists' => true,
        ];

        $orm->schemaCreate('test_schema_all', $columns, $options);

        $captured = $orm->captured;
        $this->assertNotEmpty($captured);

        $foundCreate = false;
        $foundIndex = false;
        foreach ($captured as $sql) {
            $u = strtoupper($sql);
            if (strpos($u, 'CREATE TABLE') !== false) {
                $foundCreate = true;
            }
            if (strpos($u, 'CREATE INDEX') !== false || strpos($u, 'CREATE UNIQUE INDEX') !== false) {
                $foundIndex = true;
            }
        }

        $this->assertTrue($foundCreate, 'CREATE TABLE not generated');
        $this->assertTrue($foundIndex, 'CREATE INDEX not generated');
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
                ['name' => 'fk_test_other', 'columns' => ['age'], 'refTable' => 'other', 'refColumns' => ['id'], 'onDelete' => 'cascade'],
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
        $this->assertNotEmpty($captured);

        $hasAddColumn = false;
        $hasAddIndex = false;
        $hasAddForeign = false;
        $hasDropForeign = false;
        $hasDropIndex = false;
        $hasDropColumn = false;

        foreach ($captured as $sql) {
            $u = strtoupper($sql);
            if (strpos($u, 'ADD COLUMN') !== false) {
                $hasAddColumn = true;
            }
            if (strpos($u, 'ADD CONSTRAINT') !== false || strpos($u, 'ADD INDEX') !== false) {
                $hasAddForeign = true;
                $hasAddIndex = true;
            }
            if (strpos($u, 'DROP FOREIGN KEY') !== false || strpos($u, 'DROP CONSTRAINT') !== false) {
                $hasDropForeign = true;
            }
            if (strpos($u, 'DROP INDEX') !== false || strpos($u, 'DROP KEY') !== false) {
                $hasDropIndex = true;
            }
            if (strpos($u, 'DROP COLUMN') !== false) {
                $hasDropColumn = true;
            }
        }

        $this->assertTrue($hasAddColumn, 'ADD COLUMN missing');
        $this->assertTrue($hasAddIndex, 'ADD INDEX missing');
        $this->assertTrue($hasAddForeign, 'ADD FOREIGN missing');
        $this->assertTrue($hasDropForeign, 'DROP FOREIGN missing');
        $this->assertTrue($hasDropIndex, 'DROP INDEX missing');
        $this->assertTrue($hasDropColumn, 'DROP COLUMN missing');
    }

    public function test_schema_rename_and_drop_table(): void
    {
        $orm = $this->makeOrmCollector();

        $orm->schemaRename('old_table_name', 'new_table_name');
        $orm->schemaDrop('new_table_name', true);

        $captured = $orm->captured;
        $this->assertNotEmpty($captured);

        $hasRename = false;
        $hasDrop = false;
        foreach ($captured as $sql) {
            $u = strtoupper($sql);
            if (strpos($u, 'RENAME TABLE') !== false || strpos($u, 'ALTER TABLE') !== false) {
                $hasRename = true;
            }
            if (strpos($u, 'DROP TABLE') !== false) {
                $hasDrop = true;
            }
        }

        $this->assertTrue($hasRename, 'RENAME not executed');
        $this->assertTrue($hasDrop, 'DROP TABLE not executed');
    }

    private function makeOrmCollector(): object
    {
        return new class () extends VersaORM {
            public array $captured = [];

            public function __construct()
            {
                parent::__construct(['driver' => 'pgsql']);
            }

            public function exec(string $query, array $bindings = [])
            {
                $this->captured[] = $query;

                return null;
            }
        };
    }
}
