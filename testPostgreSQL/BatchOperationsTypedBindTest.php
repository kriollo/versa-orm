<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

final class BatchOperationsTypedBindTest extends TestCase
{
    public function test_insert_many_and_update_many_delete_many(): void
    {
        $res = self::$orm
            ->table('users')
            ->insertMany([
                ['name' => 'Zara', 'email' => 'zara@example.com', 'status' => 'active'],
                ['name' => 'Yuri', 'email' => 'yuri@example.com', 'status' => 'inactive'],
            ], batchSize: 1000);
        static::assertSame('success', $res['status'] ?? null);
        static::assertSame(2, $res['total_inserted'] ?? 0);

        $resU = self::$orm
            ->table('users')
            ->where('id', '>=', 1)
            ->updateMany(['status' => 'checked'], maxRecords: 1000);
        static::assertSame('success', $resU['status'] ?? null);
        static::assertGreaterThanOrEqual(2, $resU['rows_affected'] ?? 0);

        $resD = self::$orm->table('users')->where('id', '>', 1000000)->deleteMany(maxRecords: 1000);
        static::assertSame('success', $resD['status'] ?? null);
        static::assertSame(0, $resD['rows_affected'] ?? -1);
    }

    public function test_raw_select_with_param_binding(): void
    {
        $rows = self::$orm->exec('SELECT COUNT(*) AS c FROM users WHERE id > ?', [1]);
        static::assertIsArray($rows);
        static::assertArrayHasKey(0, $rows);
        static::assertArrayHasKey('c', $rows[0]);
        static::assertIsNumeric($rows[0]['c']);
    }
}
