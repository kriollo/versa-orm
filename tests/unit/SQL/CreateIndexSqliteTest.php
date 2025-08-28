<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
final class CreateIndexSqliteTest extends TestCase
{
    public function test_schema_create_omits_using_and_mysql_options_on_sqlite(): void
    {
        $orm = new class () extends VersaORM {
            public array $captured = [];

            public function __construct()
            {
                parent::__construct();
            }

            public function exec(string $query, array $bindings = [])
            {
                $this->captured[] = $query;

                return null;
            }
        };

        // Forzar driver sqlite en la instancia (entornos de phpunit pueden sobrescribir env)
        $orm->setConfig(['driver' => 'sqlite']);

        $columns = [
            ['name' => 'id', 'type' => 'INTEGER', 'nullable' => false, 'primary' => true, 'autoIncrement' => true],
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

        $orm->schemaCreate('versa_users', $columns, $options);

        $captured = $orm->captured;
        $this->assertNotEmpty($captured);

        $createSql = $captured[0] ?? '';
        // SQLite should not get engine/charset/collation in create table
        $this->assertStringNotContainsStringIgnoringCase('ENGINE=', $createSql);
        $this->assertStringNotContainsStringIgnoringCase('CHARSET=', $createSql);
        $this->assertStringNotContainsStringIgnoringCase('COLLATE=', $createSql);

        // Index SQL (captured later) should not contain USING
        $foundIndex = false;
        foreach ($captured as $sql) {
            if (stripos($sql, 'CREATE INDEX') !== false) {
                $foundIndex = true;
                $this->assertStringNotContainsStringIgnoringCase('USING', $sql);
            }
        }

        $this->assertTrue($foundIndex, 'No CREATE INDEX captured');
    }
}
