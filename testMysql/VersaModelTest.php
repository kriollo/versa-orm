<?php

// tests/VersaModelTest.php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * @group mysql
 */
class VersaModelTest extends TestCase
{
    public function test_dispense_and_create(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'Heidi';
        $user->email = 'heidi@example.com';
        $user->status = 'active';
        $user->store();

        static::assertNotNull($user->id, 'ID should be set after storing.');

        $dbUser = VersaModel::load('users', $user->id);
        static::assertSame('Heidi', $dbUser->name);
    }

    public function test_load(): void
    {
        $user = VersaModel::load('users', 1);
        static::assertInstanceOf(VersaModel::class, $user);
        static::assertSame('Alice', $user->name);
    }

    public function test_load_returns_null_for_non_existent(): void
    {
        $user = VersaModel::load('users', 999);
        static::assertNull($user);
    }

    public function test_update(): void
    {
        $user = VersaModel::load('users', 1);
        $user->name = 'Alicia';
        $user->status = 'away';
        $user->store();

        $updatedUser = VersaModel::load('users', 1);
        static::assertSame('Alicia', $updatedUser->name);
        static::assertSame('away', $updatedUser->status);
    }

    public function test_trash(): void
    {
        $user = VersaModel::load('users', 2);
        static::assertNotNull($user);

        $user->trash();

        $deletedUser = VersaModel::load('users', 2);
        static::assertNull($deletedUser);
    }

    public function test_magic_methods(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'Test';
        static::assertSame('Test', $user->name);

        static::assertTrue(isset($user->name));
        static::assertFalse(isset($user->non_existent_prop));

        $user->name = null;
        static::assertFalse(isset($user->name));
    }

    public function test_export(): void
    {
        $user = VersaModel::load('users', 1);
        $data = $user->export();

        static::assertIsArray($data);
        static::assertSame(1, $data['id']);
        static::assertSame('Alice', $data['name']);
    }

    public function test_export_all(): void
    {
        $users = VersaModel::findAll('users', 'status = ?', ['active']);
        $data = VersaModel::exportAll($users);

        static::assertCount(2, $data);
        static::assertIsArray($data[0]);
        static::assertSame('Alice', $data[0]['name']);
    }

    public function test_find_all_static(): void
    {
        $users = VersaModel::findAll('users', 'id > ?', [1]);
        static::assertCount(2, $users);
        static::assertInstanceOf(VersaModel::class, $users[0]);
    }

    public function test_find_one_static(): void
    {
        $user = VersaModel::findOne('users', 1);
        static::assertInstanceOf(VersaModel::class, $user);
        static::assertSame(1, $user->id);
    }

    public function test_count_static(): void
    {
        $count = VersaModel::count('users', 'status = ?', ['active']);
        static::assertSame(2, $count);
    }
}
