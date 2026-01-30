<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaORM;
use VersaORM\VersaORMException;

use function count;
use function is_array;
use function is_string;

require_once __DIR__ . '/TestCase.php';

/**
 * @group sqlite
 */
class VersaORMTest extends TestCase
{
    public function test_connection(): void
    {
        static::assertNotNull(self::$orm, 'ORM instance should not be null');
        static::assertInstanceOf(VersaORM::class, self::$orm);
    }

    public function test_exec_select(): void
    {
        $users = self::$orm->exec('SELECT * FROM users WHERE status = ? ORDER BY id ASC', ['active']);
        static::assertCount(2, $users);
        static::assertSame('Alice', $users[0]['name']);
        static::assertSame('Charlie', $users[1]['name']);
    }

    public function test_exec_insert()
    {
        $query = "INSERT INTO users (name, email) VALUES ('Test User Exec', 'exec@test.com')";
        $result = self::$orm->exec($query);

        static::assertTrue(
            $result === null || is_array($result) && count($result) === 0,
            'exec() should return null or empty array for non-select statements',
        );
    }

    public function test_exec_update(): void
    {
        self::$orm->exec('UPDATE users SET status = ? WHERE email = ?', ['banned', 'alice@example.com']);
        $user = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        static::assertSame('banned', $user->status);
    }

    public function test_exec_delete(): void
    {
        self::$orm->exec('DELETE FROM users WHERE email = ?', ['alice@example.com']);
        $user = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        static::assertNull($user);
    }

    public function test_transaction_success(): void
    {
        self::$orm->exec('BEGIN TRANSACTION');
        self::$orm->exec("UPDATE users SET status = 'pending' WHERE email = ?", ['alice@example.com']);
        self::$orm->exec("UPDATE users SET status = 'pending' WHERE email = ?", ['bob@example.com']);
        self::$orm->exec('COMMIT');

        $alice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        $bob = self::$orm->table('users')->where('email', '=', 'bob@example.com')->findOne();

        static::assertSame('pending', $alice->status);
        static::assertSame('pending', $bob->status);
    }

    public function test_transaction_rollback(): void
    {
        // Primero obtener el estado actual de Alice
        $alice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        $originalStatus = $alice->status;

        self::$orm->exec('BEGIN TRANSACTION');
        self::$orm->exec("UPDATE users SET status = 'rollback_test' WHERE email = ?", ['alice@example.com']);

        // Verificar que el cambio temporal existe
        $tempAlice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        static::assertSame('rollback_test', $tempAlice->status);

        // Hacer rollback
        self::$orm->exec('ROLLBACK');

        // Verificar que volvió al estado original
        $alice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        static::assertSame($originalStatus, $alice->status);
    }

    public function test_schema_get_tables(): void
    {
        $tables = self::$orm->schema('tables');
        static::assertContains('users', $tables);
        static::assertContains('posts', $tables);
        static::assertContains('products', $tables);
    }

    public function test_schema_get_columns(): void
    {
        $columns = self::$orm->schema('columns', 'users');
        static::assertIsArray($columns, 'Schema should return an array');
        static::assertNotEmpty($columns, 'Schema should not be empty');

        // The schema can return different structures - check for column names as values or keys
        $hasIdColumn = false;
        $hasNameColumn = false;
        $hasEmailColumn = false;

        // Try to find columns either as keys or values
        foreach ($columns as $key => $value) {
            if (is_string($key)) {
                // Column names as keys
                if (strtolower($key) === 'id') {
                    $hasIdColumn = true;
                }

                if (strtolower($key) === 'name') {
                    $hasNameColumn = true;
                }

                if (strtolower($key) === 'email') {
                    $hasEmailColumn = true;
                }
            } elseif (is_string($value)) {
                // Column names as values
                if (strtolower($value) === 'id') {
                    $hasIdColumn = true;
                }

                if (strtolower($value) === 'name') {
                    $hasNameColumn = true;
                }

                if (strtolower($value) === 'email') {
                    $hasEmailColumn = true;
                }
            } elseif (is_array($value) && isset($value['name'])) {
                // Column info in array format
                if (strtolower($value['name']) === 'id') {
                    $hasIdColumn = true;
                }

                if (strtolower($value['name']) === 'name') {
                    $hasNameColumn = true;
                }

                if (strtolower($value['name']) === 'email') {
                    $hasEmailColumn = true;
                }
            }
        }

        static::assertTrue($hasIdColumn, 'Schema should include id column');
        static::assertTrue($hasNameColumn, 'Schema should include name column');
        static::assertTrue($hasEmailColumn, 'Schema should include email column');
    }

    public function test_throws_exception_on_invalid_query(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->exec('SELECT * FROM non_existent_table');
    }
}
