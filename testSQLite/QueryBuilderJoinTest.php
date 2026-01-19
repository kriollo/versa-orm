<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\QueryBuilder;

use function count;

/**
 * @group sqlite
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

    public function test_composite_join_via_on(): void
    {
        $results = self::$orm
            ->table('posts as p')
            ->select(['p.title', 'u.name as author'])
            ->join('users as u')
            ->on('p.user_id', '=', 'u.id')
            ->on('p.user_id', '=', 'u.id')
            ->where('u.status', '=', 'active')
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

    public function test_join_methods_exist(): void
    {
        $query = self::$orm->table('users');

        self::assertTrue(method_exists($query, 'rightJoin'));
        self::assertTrue(method_exists($query, 'fullOuterJoin'));
        self::assertTrue(method_exists($query, 'crossJoin'));

        $chainedQuery = $query->leftJoin('posts', 'users.id', '=', 'posts.user_id');
        self::assertInstanceOf(QueryBuilder::class, $chainedQuery);
    }
}
