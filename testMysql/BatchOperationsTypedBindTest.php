<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

final class BatchOperationsTypedBindTest extends TestCase
{
    public function testInsertManyAndUpdateManyDeleteMany(): void
    {
        $res = self::$orm->table('users')
            ->insertMany([
                ['name' => 'Zara', 'email' => 'zara@example.com', 'status' => 'active'],
                ['name' => 'Yuri', 'email' => 'yuri@example.com', 'status' => 'inactive'],
            ], batchSize: 1000);
        $this->assertEquals('success', $res['status'] ?? null);
        $this->assertEquals(2, $res['total_inserted'] ?? 0);

        $resU = self::$orm->table('users')
            ->where('id', '>=', 1)
            ->updateMany(['status' => 'checked'], maxRecords: 1000);
        $this->assertEquals('success', $resU['status'] ?? null);
        $this->assertGreaterThanOrEqual(2, $resU['rows_affected'] ?? 0);

        $resD = self::$orm->table('users')
            ->where('id', '>', 1000000)
            ->deleteMany(maxRecords: 1000);
        $this->assertEquals('success', $resD['status'] ?? null);
        $this->assertEquals(0, $resD['rows_affected'] ?? -1);
    }

    public function testRawSelectWithParamBinding(): void
    {
        $rows = self::$orm->exec('SELECT COUNT(*) AS c FROM users WHERE id > ?', [1]);
        $this->assertIsArray($rows);
        $this->assertArrayHasKey(0, $rows);
        $this->assertArrayHasKey('c', $rows[0]);
        $this->assertIsNumeric($rows[0]['c']);
    }
}
