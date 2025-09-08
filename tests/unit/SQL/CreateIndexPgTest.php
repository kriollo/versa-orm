<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * @group postgresql
 */
final class CreateIndexPgTest extends TestCase
{
    public function test_schema_create_generates_using_in_postgres(): void
    {
        $orm = new class() extends VersaORM {
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
                ['name' => 'id_empresa', 'columns' => ['id_empresa'], 'unique' => false, 'using' => 'btree'],
            ],
            'if_not_exists' => true,
        ];

        $orm->schemaCreate('versa_users', $columns, $options);

        $captured = $orm->captured;
        self::assertNotEmpty($captured);

        $found = false;
        foreach ($captured as $sql) {
            if (stripos($sql, 'CREATE INDEX') !== false) {
                $found = true;
                self::assertStringContainsStringIgnoringCase('USING', $sql);
                // Ensure USING is present before '('
                self::assertMatchesRegularExpression('/USING\s+\w+\s*\(/i', $sql);
            }
        }

        self::assertTrue($found, 'No CREATE INDEX captured');
    }
}
