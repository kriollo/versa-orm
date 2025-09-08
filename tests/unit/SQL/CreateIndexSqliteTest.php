<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
final class CreateIndexSqliteTest extends TestCase
{
    public function test_schema_create_generates_valid_index_sql_for_sqlite(): void
    {
        $orm = new class() extends VersaORM {
            public array $captured = [];

            public function __construct()
            {
                parent::__construct(['driver' => 'sqlite']);
            }

            public function exec(string $query, array $bindings = [])
            {
                $this->captured[] = $query;

                return null;
            }
        };

        $columns = [
            ['name' => 'id', 'type' => 'INTEGER', 'nullable' => false, 'primary' => true, 'autoIncrement' => true],
            ['name' => 'id_empresa', 'type' => 'INTEGER', 'nullable' => false],
            ['name' => 'created_at', 'type' => 'DATETIME', 'nullable' => true],
            ['name' => 'updated_at', 'type' => 'DATETIME', 'nullable' => true],
        ];

        $options = [
            'indexes' => [
                ['name' => 'id_empresa', 'columns' => ['id_empresa'], 'unique' => false, 'using' => 'BTREE'],
            ],
            'if_not_exists' => true,
        ];

        $orm->schemaCreate('versa_users', $columns, $options);

        $captured = $orm->captured;
        self::assertNotEmpty($captured, 'No SQL captured');

        $indexSqlFound = false;

        foreach ($captured as $sql) {
            if (stripos($sql, 'CREATE INDEX') !== false) {
                $indexSqlFound = true;
                // En sqlite no debería incluir USING BTREE
                self::assertStringNotContainsString('USING BTREE', strtoupper($sql));
            }
        }

        self::assertTrue($indexSqlFound, 'No CREATE INDEX statement captured');
    }

    public function test_schema_alter_drop_column_and_index_generates_valid_sql_for_sqlite(): void
    {
        $orm = new class() extends VersaORM {
            public array $captured = [];

            public function __construct()
            {
                parent::__construct(['driver' => 'sqlite']);
            }

            public function exec(string $query, array $bindings = [])
            {
                $this->captured[] = $query;

                return null;
            }
        };

        $orm->schemaAlter('versa_users', [
            'drop' => [
                ['name' => 'id_empresa'],
            ],
            'drop_indexes' => [
                ['name' => 'id_empresa'],
            ],
        ]);

        $captured = $orm->captured;
        self::assertNotEmpty($captured, 'No SQL captured from schemaAlter');

        $dropColumnFound = false;
        $dropIndexFound = false;

        foreach ($captured as $sql) {
            $upper = strtoupper($sql);
            if (str_contains($upper, 'DROP COLUMN') || str_contains($upper, 'DROP `ID_EMPRESA`')) {
                $dropColumnFound = true;
            }
            if (str_contains($upper, 'DROP INDEX') || str_contains($upper, 'DROP KEY')) {
                $dropIndexFound = true;
            }
        }

        self::assertTrue($dropColumnFound, 'No DROP COLUMN statement captured');
        self::assertTrue($dropIndexFound, 'No DROP INDEX statement captured');
    }
}
