<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * @group mysql
 */
class StoreAllTest extends TestCase
{
    public function test_store_all_inserts_multiple_models(): void
    {
        $u1 = VersaModel::dispense('users');
        $u1->name = 'BatchM1';
        $u1->email = 'batch_m1_mysql@example.com';
        $u1->status = 'active';

        $u2 = VersaModel::dispense('users');
        $u2->name = 'BatchM2';
        $u2->email = 'batch_m2_mysql@example.com';
        $u2->status = 'active';

        $ids = VersaModel::storeAll([$u1, $u2]);
        self::assertCount(2, $ids);
        self::assertNotNull($ids[0]);
        self::assertNotNull($ids[1]);
        self::assertSame($ids[0], $u1->id);
        self::assertSame($ids[1], $u2->id);
    }

    public function test_store_all_with_empty_array_returns_empty(): void
    {
        self::assertSame([], VersaModel::storeAll([]));
    }
}
