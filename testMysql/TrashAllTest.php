<?php

// testMysql/TrashAllTest.php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * @group mysql
 */
class TrashAllTest extends TestCase
{
    public function testTrashAllRemovesAllModels(): void
    {
        // Crear y guardar varios usuarios
        $users = [];
        for ($i = 0; $i < 3; $i++) {
            $user = VersaModel::dispense('users');
            $user->name = 'User ' . $i;
            $user->email = 'user' . $i . '@example.com';
            $user->status = 'active';
            $user->store();
            $users[] = $user;
        }

        // Verificar que existen en la base de datos
        foreach ($users as $user) {
            $dbUser = VersaModel::load('users', $user->id);
            self::assertNotNull($dbUser);
        }

        // Eliminar todos con trashAll
        VersaModel::trashAll($users);

        // Verificar que fueron eliminados
        foreach ($users as $user) {
            $deletedUser = VersaModel::load('users', $user->id);
            self::assertNull($deletedUser);
        }
    }

    public function testTrashAllWithEmptyArrayDoesNothing(): void
    {
        VersaModel::trashAll([]); // No debe lanzar excepción
        self::assertTrue(true);
    }

    public function testTrashAllThrowsOnInvalidInput(): void
    {
        $this->expectException(\VersaORM\VersaORMException::class);
        VersaModel::trashAll(['no es modelo']);
    }
}
