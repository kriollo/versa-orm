<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

/**
 * @group mysql
 */
final class DDLAlterOperationsTest extends TestCase
{
    public function testAddAndDropIndexAndForeign(): void
    {
        $orm = self::$orm;
        // base tables
        $orm->schemaCreate('dept', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(100)'],
        ], ['engine' => 'InnoDB']);
        $orm->schemaCreate('emp', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'dept_id', 'type' => 'INT'],
            ['name' => 'email', 'type' => 'VARCHAR(191)'],
        ], ['engine' => 'InnoDB']);

        // add index simple
        $orm->schemaAlter('emp', [
            'addIndex' => [['name' => 'idx_emp_email', 'columns' => ['email']]],
        ]);
        $idx = $orm->schema('indexes', 'emp');
        self::assertIsArray($idx);
        self::assertNotEmpty($idx);

        // add foreign key
        $orm->schemaAlter('emp', [
            'addForeign' => [[
                'name'       => 'fk_emp_dept',
                'columns'    => ['dept_id'],
                'refTable'   => 'dept',
                'refColumns' => ['id'],
                'onDelete'   => 'cascade',
            ]],
        ]);
        $orm->table('dept')->insert(['name' => 'IT']);
        $orm->table('emp')->insert(['dept_id' => 1, 'email' => 'x@x.com']);

        // drop index y fk
        $orm->schemaAlter('emp', ['dropIndex' => ['idx_emp_email']]);
        $orm->schemaAlter('emp', ['dropForeign' => ['fk_emp_dept']]);
        $idx2 = $orm->schema('indexes', 'emp');
        self::assertIsArray($idx2);

        // cleanup
        $orm->schemaDrop('emp');
        $orm->schemaDrop('dept');
    }

    public function testRenameModifyDropColumns(): void
    {
        $orm = self::$orm;
        $orm->schemaCreate('tddl', [
            ['name' => 'a', 'type' => 'INT'],
            ['name' => 'b', 'type' => 'VARCHAR(50)'],
        ], ['engine' => 'InnoDB']);

        // rename a -> a_id
        $orm->schemaAlter('tddl', ['rename' => [['from' => 'a', 'to' => 'a_id']]]);
        // modify b to VARCHAR(200) NOT NULL DEFAULT ''
        $orm->schemaAlter('tddl', ['modify' => [['name' => 'b', 'type' => 'VARCHAR(200)', 'nullable' => false, 'default' => '']]]);
        // drop column b
        $orm->schemaAlter('tddl', ['drop' => ['b']]);

        $cols  = $orm->schema('columns', 'tddl');
        $names = array_map(static fn ($c) => (string) ($c['name'] ?? $c['column_name'] ?? ''), $cols);
        self::assertContains('a_id', $names);
        self::assertNotContains('a', $names);
        self::assertNotContains('b', $names);

        $orm->schemaDrop('tddl');
    }
}
