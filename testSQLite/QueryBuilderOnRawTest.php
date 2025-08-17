<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaORMException;

/**
 * @group sqlite
 */
class QueryBuilderOnRawTest extends TestCase
{
    public function testOnRawSimple(): void
    {
        $rows = self::$orm->table('posts as p')
            ->select(['p.title'])
            ->join('users as u')
            ->onRaw('p.user_id = u.id AND u.status = ?', ['active'])
            ->getAll();

        self::assertNotEmpty($rows);
        foreach ($rows as $r) {
            self::assertArrayHasKey('title', $r);
        }
    }

    public function testOnRawWithAdditionalOn(): void
    {
        $rows = self::$orm->table('posts as p')
            ->select(['p.title'])
            ->join('users as u')
            ->on('p.user_id', '=', 'u.id')
            ->onRaw('(u.status = ? OR u.status = ?)', ['active', 'inactive'])
            ->where('u.status', '=', 'active')
            ->getAll();

        self::assertNotEmpty($rows);
    }

    public function testMultipleOnRaw(): void
    {
        $rows = self::$orm->table('posts as p')
            ->select(['p.title'])
            ->join('users as u')
            ->onRaw('p.user_id = u.id', [])
            ->onRaw('u.status = ?', ['active'])
            ->getAll();

        self::assertNotEmpty($rows);
    }

    public function testOnRawBindingsApplied(): void
    {
        $rows = self::$orm->table('posts as p')
            ->select(['p.title'])
            ->join('users as u')
            ->onRaw('p.user_id = u.id AND p.title LIKE ?', ['%Post%'])
            ->where('u.status', '=', 'active')
            ->getAll();

        self::assertNotEmpty($rows);
        foreach ($rows as $r) {
            self::assertStringContainsString('Post', $r['title']);
        }
    }

    public function testOnRawSecurityRejectsSemicolon(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->table('posts as p')
            ->join('users as u')
            ->onRaw('p.user_id = u.id; DROP TABLE users', []);
    }

    public function testOnRawSecurityRejectsComment(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->table('posts as p')
            ->join('users as u')
            ->onRaw('p.user_id = u.id -- comentario', []);
    }

    public function testOnRawSecurityRejectsDangerousKeyword(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->table('posts as p')
            ->join('users as u')
            ->onRaw('p.user_id = u.id OR 1=1 DROP TABLE x', []);
    }
}
