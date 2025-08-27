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

        $orm = new class () extends VersaORM {
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
        $this->assertNotEmpty($captured, 'No SQL captured');

        // Buscar SQL de creación de índice (debería ser algo como: CREATE INDEX `id_empresa` ON `versa_users` USING BTREE (`id_empresa`)
        $indexSqlFound = false;

        foreach ($captured as $sql) {
            if (stripos($sql, 'CREATE INDEX') !== false) {
                $indexSqlFound = true;
                // No debe contener 'USING BTREE (' seguido inmediatamente por '('
                $this->assertStringNotContainsString('USING BTREE (', strtoupper($sql));
                // Debe contener 'USING BTREE' y la lista de columnas entre paréntesis
                $this->assertStringContainsString('USING BTREE', strtoupper($sql));
                $this->assertStringContainsString('(', $sql);
                $this->assertStringContainsString(')', $sql);
            }
        }

        $this->assertTrue($indexSqlFound, 'No CREATE INDEX statement captured');
    }
}
