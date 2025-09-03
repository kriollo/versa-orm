<?php

// testSQLite/TrashAllTest.php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * @group sqlite
 */
class TrashAllTest extends TestCase
{
    public function test_trash_all_removes_all_models(): void
    {
        $users = [];
        for ($i = 0; $i < 3; $i++) {
            $user = VersaModel::dispense('users');
            $user->name = 'UserSQL ' . $i;
            $user->email = 'usersql' . $i . '@example.com';
            $user->status = 'active';
            $user->store();
            $users[] = $user;
        }
        foreach ($users as $user) {
            $dbUser = VersaModel::load('users', $user->id);
            static::assertNotNull($dbUser);
        }
        VersaModel::trashAll($users);
        foreach ($users as $user) {
            $deletedUser = VersaModel::load('users', $user->id);
            static::assertNull($deletedUser);
        }
    }

    public function test_trash_all_with_empty_array_does_nothing(): void
    {
        VersaModel::trashAll([]);
        static::assertTrue(true);
    }

    public function test_trash_all_throws_on_invalid_input(): void
    {
        $this->expectException(\VersaORM\VersaORMException::class);
        VersaModel::trashAll(['no es modelo']);
    }
}
