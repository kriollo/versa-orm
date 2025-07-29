<?php

// tests/VersaORMTest.php

declare(strict_types=1);

namespace VersaORM\Tests;

use VersaORM\VersaORMException;

class VersaORMTest extends TestCase
{
    public function testConnection(): void
    {
        $this->assertNotNull(self::$orm, 'ORM instance should not be null');
        $this->assertInstanceOf(\VersaORM\VersaORM::class, self::$orm);
    }

    public function testExecSelect(): void
    {
        $users = self::$orm->exec('SELECT * FROM users WHERE status = ? ORDER BY id ASC', ['active']);
        $this->assertCount(2, $users);
        $this->assertEquals('Alice', $users[0]['name']);
        $this->assertEquals('Charlie', $users[1]['name']);
    }

    public function testExecInsert(): void
    {
        $result = self::$orm->exec("INSERT INTO users (name, email, status) VALUES (?, ?, ?)", ['David', 'david@example.com', 'active']);
        $this->assertNull($result); // INSERT no devuelve datos

        $user = self::$orm->table('users')->where('email', '=', 'david@example.com')->findOne();
        $this->assertNotNull($user);
        $this->assertEquals('David', $user->name);
    }

    public function testExecUpdate(): void
    {
        self::$orm->exec("UPDATE users SET status = ? WHERE email = ?", ['banned', 'alice@example.com']);
        $user = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        $this->assertEquals('banned', $user->status);
    }

    public function testExecDelete(): void
    {
        self::$orm->exec("DELETE FROM users WHERE email = ?", ['alice@example.com']);
        $user = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        $this->assertNull($user);
    }

    public function testTransactionSuccess(): void
    {
        self::$orm->exec('START TRANSACTION');
        self::$orm->exec("UPDATE users SET status = 'pending' WHERE email = ?", ['alice@example.com']);
        self::$orm->exec("UPDATE users SET status = 'pending' WHERE email = ?", ['bob@example.com']);
        self::$orm->exec('COMMIT');

        $alice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        $bob = self::$orm->table('users')->where('email', '=', 'bob@example.com')->findOne();

        $this->assertEquals('pending', $alice->status);
        $this->assertEquals('pending', $bob->status);
    }

    public function testTransactionRollback(): void
    {
        self::$orm->exec('START TRANSACTION');
        self::$orm->exec("UPDATE users SET status = 'pending' WHERE email = ?", ['alice@example.com']);
        self::$orm->exec('ROLLBACK');

        $alice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        $this->assertEquals('active', $alice->status); // Should be back to original state
    }

    public function testSchemaGetTables(): void
    {
        $tables = self::$orm->schema('tables');
        $this->assertContains('users', $tables);
        $this->assertContains('posts', $tables);
        $this->assertContains('products', $tables);
    }

    public function testSchemaGetColumns(): void
    {
        $columns = self::$orm->schema('columns', 'users');
        $this->assertArrayHasKey('id', $columns);
        $this->assertArrayHasKey('name', $columns);
        $this->assertArrayHasKey('email', $columns);
        $this->assertStringContainsString('int', $columns['id']['type']);
        $this->assertTrue($columns['id']['primary']);
    }

    public function testThrowsExceptionOnInvalidQuery(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->exec('SELECT * FROM non_existent_table');
    }
}
