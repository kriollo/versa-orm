<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaORMException;

/**
 * @group mysql
 */
class QueryBuilderOnRawTest extends TestCase
{
    public function test_on_raw_simple(): void
    {
        $rows = self::$orm
            ->table('posts as p')
            ->select(['p.title'])
            ->join('users as u')
            ->onRaw('p.user_id = u.id AND u.status = ?', ['active'])
            ->getAll();

        self::assertIsArray($rows);
    }

    public function test_on_raw_with_additional_on(): void
    {
        $rows = self::$orm
            ->table('posts as p')
            ->select(['p.title'])
            ->join('users as u')
            ->on('p.user_id', '=', 'u.id')
            ->onRaw('(u.status = ? OR u.status = ?)', ['active', 'inactive'])
            ->where('u.status', '=', 'active')
            ->getAll();

        self::assertIsArray($rows);
    }

    public function test_multiple_on_raw(): void
    {
        $rows = self::$orm
            ->table('posts as p')
            ->select(['p.title'])
            ->join('users as u')
            ->onRaw('p.user_id = u.id', [])
            ->onRaw('u.status = ?', ['active'])
            ->getAll();

        self::assertIsArray($rows);
    }

    public function test_on_raw_bindings_applied(): void
    {
        $rows = self::$orm
            ->table('posts as p')
            ->select(['p.title'])
            ->join('users as u')
            ->onRaw('p.user_id = u.id AND p.title LIKE ?', ['%Post%'])
            ->where('u.status', '=', 'active')
            ->getAll();

        self::assertIsArray($rows);
    }

    public function test_on_raw_security_rejects_semicolon(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->table('posts as p')->join('users as u')->onRaw('p.user_id = u.id; DROP TABLE users', []);
    }

    public function test_on_raw_security_rejects_comment(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->table('posts as p')->join('users as u')->onRaw('p.user_id = u.id -- comentario', []);
    }

    public function test_on_raw_security_rejects_dangerous_keyword(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->table('posts as p')->join('users as u')->onRaw('p.user_id = u.id OR 1=1 DROP TABLE x', []);
    }
}
