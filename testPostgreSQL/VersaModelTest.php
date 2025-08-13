<?php

// tests/VersaModelTest.php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

class VersaModelTest extends TestCase
{
    public function testDispenseAndCreate(): void
    {
        $user         = VersaModel::dispense('users');
        $user->name   = 'Heidi';
        $user->email  = 'heidi@example.com';
        $user->status = 'active';
        $user->store();

        self::assertNotNull($user->id, 'ID should be set after storing.');

        $dbUser = VersaModel::load('users', $user->id);
        self::assertSame('Heidi', $dbUser->name);
    }

    public function testLoad(): void
    {
        $user = VersaModel::load('users', 1);
        self::assertInstanceOf(VersaModel::class, $user);
        self::assertSame('Alice', $user->name);
    }

    public function testLoadReturnsNullForNonExistent(): void
    {
        $user = VersaModel::load('users', 999);
        self::assertNull($user);
    }

    public function testUpdate(): void
    {
        $user         = VersaModel::load('users', 1);
        $user->name   = 'Alicia';
        $user->status = 'away';
        $user->store();

        $updatedUser = VersaModel::load('users', 1);
        self::assertSame('Alicia', $updatedUser->name);
        self::assertSame('away', $updatedUser->status);
    }

    public function testTrash(): void
    {
        $user = VersaModel::load('users', 2);
        self::assertNotNull($user);

        $user->trash();

        $deletedUser = VersaModel::load('users', 2);
        self::assertNull($deletedUser);
    }

    public function testMagicMethods(): void
    {
        $user       = VersaModel::dispense('users');
        $user->name = 'Test';
        self::assertSame('Test', $user->name);

        self::assertTrue(isset($user->name));
        self::assertFalse(isset($user->non_existent_prop));

        $user->name = null;
        self::assertFalse(isset($user->name));
    }

    public function testExport(): void
    {
        $user = VersaModel::load('users', 1);
        $data = $user->export();

        self::assertIsArray($data);
        self::assertSame(1, $data['id']);
        self::assertSame('Alice', $data['name']);
    }

    public function testExportAll(): void
    {
        $users = VersaModel::findAll('users', 'status = ?', ['active']);
        $data  = VersaModel::exportAll($users);

        self::assertCount(2, $data);
        self::assertIsArray($data[0]);
        self::assertSame('Alice', $data[0]['name']);
    }

    public function testFindAllStatic(): void
    {
        $users = VersaModel::findAll('users', 'id > ?', [1]);
        self::assertCount(2, $users);
        self::assertInstanceOf(VersaModel::class, $users[0]);
    }

    public function testFindOneStatic(): void
    {
        $user = VersaModel::findOne('users', 1);
        self::assertInstanceOf(VersaModel::class, $user);
        self::assertSame(1, $user->id);
    }

    public function testCountStatic(): void
    {
        $count = VersaModel::count('users', 'status = ?', ['active']);
        self::assertSame(2, $count);
    }
}
