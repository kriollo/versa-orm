<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * @group postgresql
 */
final class CreateIndexPostgresTest extends TestCase
{
    public function test_schema_create_generates_valid_index_sql_for_postgres(): void
    {
        $orm = new class () extends VersaORM {
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

        $columns = [
            ['name' => 'id', 'type' => 'INT', 'nullable' => false, 'primary' => true, 'autoIncrement' => true],
            ['name' => 'id_empresa', 'type' => 'INT', 'nullable' => false],
            ['name' => 'created_at', 'type' => 'TIMESTAMP', 'nullable' => true],
            ['name' => 'updated_at', 'type' => 'TIMESTAMP', 'nullable' => true],
        ];

        $options = [
            'indexes' => [
                ['name' => 'id_empresa', 'columns' => ['id_empresa'], 'unique' => false, 'using' => 'BTREE'],
            ],
            'if_not_exists' => true,
        ];

        $orm->schemaCreate('versa_users', $columns, $options);

        $captured = $orm->captured;
        $this->assertNotEmpty($captured, 'No SQL captured');

        $indexSqlFound = false;

        foreach ($captured as $sql) {
            if (stripos($sql, 'CREATE INDEX') !== false) {
                $indexSqlFound = true;
                // En Postgres sí esperamos USING BTREE si fue pedido
                $this->assertStringContainsString('USING BTREE', strtoupper($sql));
                $this->assertStringContainsString('(', $sql);
                $this->assertStringContainsString(')', $sql);
            }
        }

        $this->assertTrue($indexSqlFound, 'No CREATE INDEX statement captured');
    }

    public function test_schema_alter_drop_column_and_index_generates_valid_sql_for_postgres(): void
    {
        $orm = new class () extends VersaORM {
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

        $orm->schemaAlter('versa_users', [
            'drop' => [
                ['name' => 'id_empresa'],
            ],
            'drop_indexes' => [
                ['name' => 'id_empresa'],
            ],
        ]);

        $captured = $orm->captured;
        $this->assertNotEmpty($captured, 'No SQL captured from schemaAlter');

        $dropColumnFound = false;
        $dropIndexFound = false;

        foreach ($captured as $sql) {
            $upper = strtoupper($sql);
            if (strpos($upper, 'DROP COLUMN') !== false || strpos($upper, 'DROP "ID_EMPRESA"') !== false) {
                $dropColumnFound = true;
            }
            if (strpos($upper, 'DROP INDEX') !== false || strpos($upper, 'DROP CONSTRAINT') !== false) {
                $dropIndexFound = true;
            }
        }

        $this->assertTrue($dropColumnFound, 'No DROP COLUMN statement captured');
        $this->assertTrue($dropIndexFound, 'No DROP INDEX statement captured');
    }
}
