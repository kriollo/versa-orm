<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

class DDLApiTest extends TestCase
{
    public function testCreateAlterRenameDrop(): void
    {
        $orm = self::$orm;

        // Cleanup previa por si quedó algo
        $orm->schemaDrop('ddl_mvp_users');
        $orm->schemaDrop('ddl_mvp_people');

        // 1) Create
        $orm->schemaCreate('ddl_mvp_users', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(100)', 'nullable' => false],
            ['name' => 'active', 'type' => 'BOOLEAN', 'default' => true],
        ], [
            'if_not_exists' => true,
        ]);

        // Validar existencia por columns
        $cols = $orm->schema('columns', 'ddl_mvp_users');
        $this->assertIsArray($cols);
        $this->assertNotEmpty($cols);

        // 2) Alter (add column)
        $orm->schemaAlter('ddl_mvp_users', [
            'add' => [
                ['name' => 'email', 'type' => 'VARCHAR(150)', 'nullable' => true],
            ],
        ]);
        $cols2 = $orm->schema('columns', 'ddl_mvp_users');
        $colNames2 = array_map(fn($c) => strtolower($c['name'] ?? ($c['column_name'] ?? ($c['Field'] ?? ''))), $cols2);
        $this->assertContains('email', $colNames2);

        // 3) Rename
        $orm->schemaRename('ddl_mvp_users', 'ddl_mvp_people');
        $tables = $orm->schema('tables');
        $this->assertIsArray($tables);
        $this->assertTrue(in_array('ddl_mvp_people', array_map('strtolower', array_map(fn($t) => is_array($t) ? ($t['table_name'] ?? $t['name'] ?? (string)$t) : (string)$t, $tables))));

        // 4) Drop
        $orm->schemaDrop('ddl_mvp_people');
        $tablesAfter = $orm->schema('tables');
        $this->assertFalse(in_array('ddl_mvp_people', array_map('strtolower', array_map(fn($t) => is_array($t) ? ($t['table_name'] ?? $t['name'] ?? (string)$t) : (string)$t, $tablesAfter))));
    }

    public function testFreezeBlocksDDL(): void
    {
        $orm = self::$orm;
        $orm->freeze(true);
        try {
            $this->expectException(\VersaORM\VersaORMException::class);
            $orm->schemaCreate('ddl_blocked', [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true],
            ]);
        } finally {
            $orm->freeze(false);
            $orm->schemaDrop('ddl_blocked');
        }
    }
}
