<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

/**
 * @group mysql
 */
final class BatchOperationsTypedBindTest extends TestCase
{
    public function testInsertManyAndUpdateManyDeleteMany(): void
    {
        $res = self::$orm->table('users')
            ->insertMany([
                ['name' => 'Zara', 'email' => 'zara@example.com', 'status' => 'active'],
                ['name' => 'Yuri', 'email' => 'yuri@example.com', 'status' => 'inactive'],
            ], batchSize: 1000)
        ;
        self::assertSame('success', $res['status'] ?? null);
        self::assertSame(2, $res['total_inserted'] ?? 0);

        $resU = self::$orm->table('users')
            ->where('id', '>=', 1)
            ->updateMany(['status' => 'checked'], maxRecords: 1000)
        ;
        self::assertSame('success', $resU['status'] ?? null);
        self::assertGreaterThanOrEqual(2, $resU['rows_affected'] ?? 0);

        $resD = self::$orm->table('users')
            ->where('id', '>', 1000000)
            ->deleteMany(maxRecords: 1000)
        ;
        self::assertSame('success', $resD['status'] ?? null);
        self::assertSame(0, $resD['rows_affected'] ?? -1);
    }

    public function testRawSelectWithParamBinding(): void
    {
        $rows = self::$orm->exec('SELECT COUNT(*) AS c FROM users WHERE id > ?', [1]);
        self::assertIsArray($rows);
        self::assertArrayHasKey(0, $rows);
        self::assertArrayHasKey('c', $rows[0]);
        self::assertIsNumeric($rows[0]['c']);
    }
}
