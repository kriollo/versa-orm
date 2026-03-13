<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEngineBatchHandlersTest extends TestCase
{
    public function test_insert_update_delete_many_handlers(): void
    {
        $engine = new PdoEngine(['driver' => 'sqlite', 'database' => ':memory:']);

        // Create table
        $engine->execute('raw', [
            'query' => 'CREATE TABLE bh_test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, v INT)',
            'bindings' => [],
        ]);

        // InsertMany
        $records = [
            ['name' => 'A', 'v' => 1],
            ['name' => 'B', 'v' => 2],
        ];

        $res = $engine->execute('insertMany', ['table' => 'bh_test', 'records' => $records]);
        static::assertIsArray($res);
        static::assertArrayHasKey('total_inserted', $res);
        static::assertSame(2, $res['total_inserted']);

        // UpdateMany (increase v by 1 for all)
        $upd = $engine->execute('updatemany', [
            'table' => 'bh_test',
            'where' => [],
            'data' => ['v' => 99],
            'max_records' => 1000,
        ]);
        static::assertIsArray($upd);
        static::assertArrayHasKey('rows_affected', $upd);

        // DeleteMany (delete where v = 99)
        $del = $engine->execute('deletemany', [
            'table' => 'bh_test',
            'where' => [['column' => 'v', 'operator' => '=', 'value' => 99]],
            'max_records' => 1000,
        ]);
        static::assertIsArray($del);
        static::assertArrayHasKey('rows_affected', $del);
    }
}
