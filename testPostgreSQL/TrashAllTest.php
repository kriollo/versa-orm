<?php

// testPostgreSQL/TrashAllTest.php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * @group postgresql
 */
class TrashAllTest extends TestCase
{
    public function testTrashAllRemovesAllModels(): void
    {
        $users = [];
        for ($i = 0; $i < 3; $i++) {
            $user = VersaModel::dispense('users');
            $user->name = 'UserPG ' . $i;
            $user->email = 'userpg' . $i . '@example.com';
            $user->status = 'active';
            $user->store();
            $users[] = $user;
        }
        foreach ($users as $user) {
            $dbUser = VersaModel::load('users', $user->id);
            self::assertNotNull($dbUser);
        }
        VersaModel::trashAll($users);
        foreach ($users as $user) {
            $deletedUser = VersaModel::load('users', $user->id);
            self::assertNull($deletedUser);
        }
    }

    public function testTrashAllWithEmptyArrayDoesNothing(): void
    {
        VersaModel::trashAll([]);
        self::assertTrue(true);
    }

    public function testTrashAllThrowsOnInvalidInput(): void
    {
        $this->expectException(\VersaORM\VersaORMException::class);
        VersaModel::trashAll(['no es modelo']);
    }
}
