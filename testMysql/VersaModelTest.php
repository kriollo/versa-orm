<?php

// tests/VersaModelTest.php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

class VersaModelTest extends TestCase
{
    public function testDispenseAndCreate(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'Heidi';
        $user->email = 'heidi@example.com';
        $user->status = 'active';
        $user->store();

        $this->assertNotNull($user->id, 'ID should be set after storing.');

        $dbUser = VersaModel::load('users', $user->id);
        $this->assertEquals('Heidi', $dbUser->name);
    }

    public function testLoad(): void
    {
        $user = VersaModel::load('users', 1);
        $this->assertInstanceOf(VersaModel::class, $user);
        $this->assertEquals('Alice', $user->name);
    }

    public function testLoadReturnsNullForNonExistent(): void
    {
        $user = VersaModel::load('users', 999);
        $this->assertNull($user);
    }

    public function testUpdate(): void
    {
        $user = VersaModel::load('users', 1);
        $user->name = 'Alicia';
        $user->status = 'away';
        $user->store();

        $updatedUser = VersaModel::load('users', 1);
        $this->assertEquals('Alicia', $updatedUser->name);
        $this->assertEquals('away', $updatedUser->status);
    }

    public function testTrash(): void
    {
        $user = VersaModel::load('users', 2);
        $this->assertNotNull($user);

        $user->trash();

        $deletedUser = VersaModel::load('users', 2);
        $this->assertNull($deletedUser);
    }

    public function testMagicMethods(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'Test';
        $this->assertEquals('Test', $user->name);

        $this->assertTrue(isset($user->name));
        $this->assertFalse(isset($user->non_existent_prop));

        unset($user->name);
        $this->assertFalse(isset($user->name));
    }

    public function testExport(): void
    {
        $user = VersaModel::load('users', 1);
        $data = $user->export();

        $this->assertIsArray($data);
        $this->assertEquals(1, $data['id']);
        $this->assertEquals('Alice', $data['name']);
    }

    public function testExportAll(): void
    {
        $users = VersaModel::findAll('users', 'status = ?', ['active']);
        $data = VersaModel::exportAll($users);

        $this->assertCount(2, $data);
        $this->assertIsArray($data[0]);
        $this->assertEquals('Alice', $data[0]['name']);
    }

    public function testFindAllStatic(): void
    {
        $users = VersaModel::findAll('users', 'id > ?', [1]);
        $this->assertCount(2, $users);
        $this->assertInstanceOf(VersaModel::class, $users[0]);
    }

    public function testFindOneStatic(): void
    {
        $user = VersaModel::findOne('users', 1);
        $this->assertInstanceOf(VersaModel::class, $user);
        $this->assertEquals(1, $user->id);
    }

    public function testCountStatic(): void
    {
        $count = VersaModel::count('users', 'status = ?', ['active']);
        $this->assertEquals(2, $count);
    }
}
