<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

final class DDLAlterOperationsTest extends TestCase
{
    public function test_add_and_drop_index_and_foreign(): void
    {
        $orm = self::$orm;
        // tabla base
        $orm->schemaCreate('dept', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(100)'],
        ]);
        $orm->schemaCreate('emp', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'dept_id', 'type' => 'INT'],
            ['name' => 'email', 'type' => 'VARCHAR(191)'],
        ]);

        // add index con expresión
        $orm->schemaAlter('emp', [
            'addIndex' => [['name' => 'idx_emp_email_expr', 'columns' => [['raw' => 'lower("email")']]]],
        ]);
        $idx = $orm->schema('indexes', 'emp');
        self::assertIsArray($idx);
        self::assertNotEmpty($idx);

        // add foreign key
        $orm->schemaAlter('emp', [
            'addForeign' => [[
                'name' => 'fk_emp_dept',
                'columns' => ['dept_id'],
                'refTable' => 'dept',
                'refColumns' => ['id'],
                'onDelete' => 'cascade',
            ]],
        ]);
        // Inserciones válidas
        $orm->table('dept')->insert(['name' => 'IT']);
        $orm->table('emp')->insert(['dept_id' => 1, 'email' => 'x@x.com']);

        // drop index y fk
        $orm->schemaAlter('emp', ['dropIndex' => ['idx_emp_email_expr']]);
        $orm->schemaAlter('emp', ['dropForeign' => ['fk_emp_dept']]);
        $idx2 = $orm->schema('indexes', 'emp');
        self::assertIsArray($idx2);

        // limpieza
        $orm->schemaDrop('emp');
        $orm->schemaDrop('dept');
    }

    public function test_rename_modify_drop_columns(): void
    {
        $orm = self::$orm;

        // Ensure table doesn't exist before creating
        try {
            $orm->schemaDrop('tddl');
        } catch (Exception) {
            // Table doesn't exist, which is fine
        }

        $orm->schemaCreate('tddl', [
            ['name' => 'a', 'type' => 'INT'],
            ['name' => 'b', 'type' => 'VARCHAR(50)'],
        ]);

        // rename a -> a_id
        $orm->schemaAlter('tddl', ['rename' => [['from' => 'a', 'to' => 'a_id']]]);
        // modify b to VARCHAR(200) NOT NULL DEFAULT ''
        $orm->schemaAlter('tddl', ['modify' => [[
            'name' => 'b',
            'type' => 'VARCHAR(200)',
            'nullable' => false,
            'default' => '',
        ]]]);
        // drop column b
        $orm->schemaAlter('tddl', ['drop' => ['b']]);

        $cols = $orm->schema('columns', 'tddl');
        $names = array_map(static fn($c) => (string) ($c['name'] ?? $c['column_name'] ?? ''), $cols);
        self::assertContains('a_id', $names);
        self::assertNotContains('a', $names);
        self::assertNotContains('b', $names);

        $orm->schemaDrop('tddl');
    }
}
