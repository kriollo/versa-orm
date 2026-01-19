<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use function count;

/**
 * @group postgresql
 */
class QueryBuilderJoinTest extends TestCase
{
    public function test_inner_join(): void
    {
        $posts = self::$orm
            ->table('posts')
            ->select(['posts.title', 'users.name as author'])
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->where('users.status', '=', 'active')
            ->getAll();

        self::assertCount(2, $posts);
        self::assertSame('Alice', $posts[0]['author']);
    }

    public function test_left_join(): void
    {
        self::$orm->table('users')->insert(['name' => 'Eve', 'email' => 'eve@example.com', 'status' => 'active']);

        $users = self::$orm
            ->table('users')
            ->select(['users.name', 'posts.id as post_id'])
            ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
            ->whereNull('posts.id')
            ->getAll();

        self::assertGreaterThanOrEqual(1, count($users));
    }

    public function test_right_join(): void
    {
        $results = self::$orm
            ->table('users')
            ->select(['users.name', 'posts.title'])
            ->rightJoin('posts', 'users.id', '=', 'posts.user_id')
            ->getAll();

        self::assertGreaterThanOrEqual(1, count($results));
    }

    public function test_full_outer_join(): void
    {
        self::$orm->table('users')->insert(['name' => 'David', 'email' => 'david@example.com', 'status' => 'active']);

        $results = self::$orm
            ->table('users')
            ->select(['users.name', 'posts.title'])
            ->fullOuterJoin('posts', 'users.id', '=', 'posts.user_id')
            ->getAll();

        self::assertGreaterThanOrEqual(3, count($results));
    }

    public function test_cross_join(): void
    {
        $results = self::$orm
            ->table('users')
            ->select(['users.name as user_name', 'posts.title as post_title'])
            ->crossJoin('posts')
            ->limit(10)
            ->getAll();

        self::assertGreaterThanOrEqual(1, count($results));
    }

    public function test_multiple_joins(): void
    {
        $results = self::$orm
            ->table('posts')
            ->select(['posts.title', 'users.name as author'])
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->where('users.status', '=', 'active')
            ->getAll();

        self::assertGreaterThanOrEqual(1, count($results));
    }

    public function test_join_with_complex_conditions(): void
    {
        $results = self::$orm
            ->table('users')
            ->select(['users.name', 'posts.title'])
            ->join('posts', 'users.id', '=', 'posts.user_id')
            ->where('users.status', '=', 'active')
            ->where('posts.title', 'LIKE', '%Post%')
            ->getAll();

        self::assertGreaterThanOrEqual(1, count($results));
    }
}
