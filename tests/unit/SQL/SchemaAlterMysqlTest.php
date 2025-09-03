<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * @group mysql
 */
final class SchemaAlterMysqlTest extends TestCase
{
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

        // Ejecutar schemaAlter para borrar índice y columna
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
            if (str_contains($upper, 'DROP COLUMN') || str_contains($upper, 'DROP `ID_EMPRESA`')) {
                $dropColumnFound = true;
            }
            if (str_contains($upper, 'DROP INDEX') || str_contains($upper, 'DROP KEY')) {
                $dropIndexFound = true;
            }
        }

        $this->assertTrue($dropColumnFound, 'No DROP COLUMN statement captured');
        $this->assertTrue($dropIndexFound, 'No DROP INDEX statement captured');
    }
}
