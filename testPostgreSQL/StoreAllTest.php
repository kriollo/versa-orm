<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * @group postgresql
 */
class StoreAllTest extends TestCase
{
    public function testStoreAllInsertsMultipleModels(): void
    {
        $u1 = VersaModel::dispense('users');
        $u1->name = 'BatchP1';
        $u1->email = 'batch_p1_pg@example.com';
        $u1->status = 'active';

        $u2 = VersaModel::dispense('users');
        $u2->name = 'BatchP2';
        $u2->email = 'batch_p2_pg@example.com';
        $u2->status = 'active';

        $ids = VersaModel::storeAll([$u1, $u2]);
        self::assertCount(2, $ids);
        self::assertNotNull($ids[0]);
        self::assertNotNull($ids[1]);
        self::assertSame($ids[0], $u1->id);
        self::assertSame($ids[1], $u2->id);
    }

    public function testStoreAllWithEmptyArrayReturnsEmpty(): void
    {
        self::assertSame([], VersaModel::storeAll([]));
    }
}
