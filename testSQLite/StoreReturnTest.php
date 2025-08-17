<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * @group sqlite
 */
class StoreReturnTest extends TestCase
{
    public function testStoreReturnsIdOnInsert(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'ReturnTest';
        $user->email = 'return_sqlite@example.com';
        $user->status = 'active';
        $id = $user->store();
        self::assertNotNull($id, 'store() debe devolver un ID en insert.');
        self::assertSame($id, $user->id);
    }

    public function testStoreReturnsIdOnUpdate(): void
    {
        $user = VersaModel::load('users', 1);
        $originalId = $user->id;
        $returned = $user->store(); // update sin cambios
        self::assertSame($originalId, $returned);
    }

    public function testStoreAndGetIdConvenience(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'ReturnTest2';
        $user->email = 'return2_sqlite@example.com';
        $user->status = 'active';
        $id = $user->storeAndGetId();
        self::assertNotNull($id);
        self::assertSame($id, $user->id);
    }

    public function testStaticStoreModelReturnsId(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'ReturnTest3';
        $user->email = 'return3_sqlite@example.com';
        $user->status = 'active';
        $id = VersaModel::storeModel($user);
        self::assertNotNull($id);
        self::assertSame($id, $user->id);
    }
}
