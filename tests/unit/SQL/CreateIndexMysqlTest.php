<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * @group mysql
 */
final class CreateIndexMysqlTest extends TestCase
{
    public function test_schema_create_generates_valid_index_sql_for_mysql(): void
    {
        // Creamos una subclase de VersaORM para interceptar exec() y capturar SQL
        $captured = [];

        $orm = new class() extends VersaORM {
            public array $captured = [];

            public function __construct()
            {
                parent::__construct(['driver' => 'mysql']);
            }

            public function exec(string $query, array $bindings = [])
            {
                $this->captured[] = $query;

                // Simular resultado de exec para DDL
                return null;
            }
        };

        $columns = [
            ['name' => 'id', 'type' => 'INT', 'nullable' => false, 'primary' => true, 'autoIncrement' => true],
            ['name' => 'id_empresa', 'type' => 'INT', 'nullable' => false],
            ['name' => 'created_at', 'type' => 'DATETIME', 'nullable' => true],
            ['name' => 'updated_at', 'type' => 'DATETIME', 'nullable' => true],
        ];

        $options = [
            'engine' => 'InnoDB',
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'indexes' => [
                ['name' => 'id_empresa', 'columns' => ['id_empresa'], 'unique' => false, 'using' => 'BTREE'],
            ],
            'if_not_exists' => true,
        ];

        // Ejecutar schemaCreate
        $orm->schemaCreate('versa_users', $columns, $options);

        // Obtener SQLs ejecutados
        $captured = $orm->captured;
        self::assertNotEmpty($captured, 'No SQL captured');

        // Buscar SQL de creación de índice (debería ser algo como: CREATE INDEX `id_empresa` ON `versa_users` USING BTREE (`id_empresa`)
        $indexSqlFound = false;

        foreach ($captured as $sql) {
            if (stripos($sql, 'CREATE INDEX') === false) {
                continue;
            }

            $indexSqlFound = true;
            // No debe contener 'USING BTREE (' seguido inmediatamente por '('
            self::assertStringNotContainsString('USING BTREE (', strtoupper($sql));
            // Debe contener 'USING BTREE' y la lista de columnas entre paréntesis
            self::assertStringContainsString('USING BTREE', strtoupper($sql));
            self::assertStringContainsString('(', $sql);
            self::assertStringContainsString(')', $sql);
        }

        self::assertTrue($indexSqlFound, 'No CREATE INDEX statement captured');
    }

    public function test_schema_alter_drop_column_and_index_generates_valid_sql_for_mysql(): void
    {
        $orm = new class() extends VersaORM {
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
