<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * @group mysql
 */
class StoreReturnTest extends TestCase
{
    public function test_store_returns_id_on_insert(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'ReturnTest';
        $user->email = 'return_mysql@example.com';
        $user->status = 'active';
        $id = $user->store();
        self::assertNotNull($id, 'store() debe devolver un ID en insert.');
        self::assertSame($id, $user->id);
    }

    public function test_store_returns_id_on_update(): void
    {
        $user = VersaModel::load('users', 1);
        $originalId = $user->id;
        $returned = $user->store();
        self::assertSame($originalId, $returned);
    }

    public function test_store_and_get_id_convenience(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'ReturnTest2';
        $user->email = 'return2_mysql@example.com';
        $user->status = 'active';
        $id = $user->storeAndGetId();
        self::assertNotNull($id);
        self::assertSame($id, $user->id);
    }

    public function test_static_store_model_returns_id(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'ReturnTest3';
        $user->email = 'return3_mysql@example.com';
        $user->status = 'active';
        $id = VersaModel::storeModel($user);
        self::assertNotNull($id);
        self::assertSame($id, $user->id);
    }
}
