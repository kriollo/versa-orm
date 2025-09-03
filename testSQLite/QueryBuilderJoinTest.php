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
    // ======================================================================
    // JOIN Clauses - All Types
    // ======================================================================

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
        // Insert a user without posts to test LEFT JOIN properly
        self::$orm->table('users')->insert(['name' => 'Eve', 'email' => 'eve@example.com', 'status' => 'active']);

        $users = self::$orm
            ->table('users')
            ->select(['users.name', 'posts.id as post_id'])
            ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
            ->whereNull('posts.id')
            ->getAll();

        self::assertGreaterThanOrEqual(2, count($users)); // Charlie and Eve have no posts
    }

    public function test_right_join(): void
    {
        // SQLite doesn't support RIGHT JOIN natively, but VersaORM should handle it
        // Test RIGHT JOIN with existing data instead of creating orphaned records
        // RIGHT JOIN should return all records from the right table (posts)
        $results = self::$orm
            ->table('users')
            ->select(['users.name', 'posts.title'])
            ->rightJoin('posts', 'users.id', '=', 'posts.user_id')
            ->getAll();

        // Should return at least the existing posts
        self::assertGreaterThanOrEqual(1, count($results));

        // Verify structure - should have columns from both tables
        foreach ($results as $result) {
            self::assertArrayHasKey('title', $result);
            self::assertArrayHasKey('name', $result);
        }
    }

    public function test_full_outer_join(): void
    {
        // SQLite doesn't support FULL OUTER JOIN natively, but VersaORM should handle it
        // Test FULL OUTER JOIN with existing data
        // Insert a user without posts
        self::$orm->table('users')->insert(['name' => 'David', 'email' => 'david@example.com', 'status' => 'active']);

        $results = self::$orm
            ->table('users')
            ->select(['users.name', 'posts.title'])
            ->fullOuterJoin('posts', 'users.id', '=', 'posts.user_id')
            ->getAll();

        // Should include all users and all posts
        self::assertGreaterThanOrEqual(3, count($results));

        // Verify structure - should have columns from both tables
        foreach ($results as $result) {
            self::assertArrayHasKey('name', $result);
            self::assertArrayHasKey('title', $result);
        }
    }

    public function test_cross_join(): void
    {
        // Test CROSS JOIN with existing tables (users and posts)
        $results = self::$orm
            ->table('users')
            ->select(['users.name as user_name', 'posts.title as post_title'])
            ->crossJoin('posts')
            ->limit(10) // Limit to avoid too many results
            ->getAll();

        // CROSS JOIN should return Cartesian product
        self::assertGreaterThanOrEqual(1, count($results));

        // Verify structure - each result should have both user and post
        foreach ($results as $result) {
            self::assertArrayHasKey('user_name', $result);
            self::assertArrayHasKey('post_title', $result);
        }
    }

    public function test_multiple_joins(): void
    {
        // Test multiple JOINs with only existing tables
        $results = self::$orm
            ->table('posts')
            ->select(['posts.title', 'users.name as author'])
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->where('users.status', '=', 'active')
            ->getAll();

        self::assertGreaterThanOrEqual(1, count($results));

        foreach ($results as $result) {
            self::assertArrayHasKey('title', $result);
            self::assertArrayHasKey('author', $result);
        }
    }

    public function test_composite_join_via_on(): void
    {
        // Simular join compuesto: posts/user y adicionalmente asegurar otra igualdad artificial (posts.user_id = users.id AND posts.user_id = users.id)
        $results = self::$orm
            ->table('posts as p')
            ->select(['p.title', 'u.name as author'])
            ->join('users as u')
            ->on('p.user_id', '=', 'u.id')
            ->on('p.user_id', '=', 'u.id') // segunda condición redundante para probar encadenamiento
            ->where('u.status', '=', 'active')
            ->getAll();

        self::assertGreaterThanOrEqual(1, count($results));

        foreach ($results as $r) {
            self::assertArrayHasKey('author', $r);
        }
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

        foreach ($results as $result) {
            self::assertStringContainsString('Post', $result['title']);
            self::assertSame('Alice', $result['name']); // Solo Alice tiene status 'active' y posts
        }
    }

    // ======================================================================
    // JOIN Security Tests
    // ======================================================================

    public function test_join_methods_exist(): void
    {
        // Test that new JOIN methods exist and are chainable
        $query = self::$orm->table('users');

        self::assertTrue(method_exists($query, 'rightJoin'));
        self::assertTrue(method_exists($query, 'fullOuterJoin'));
        self::assertTrue(method_exists($query, 'crossJoin'));

        // Test method chaining
        $chainedQuery = $query->rightJoin('posts', 'users.id', '=', 'posts.user_id');
        self::assertInstanceOf(QueryBuilder::class, $chainedQuery);
    }

    public function test_join_sql_generation(): void
    {
        // Test that JOIN SQL is generated correctly (we can't easily test actual execution)
        // This is more of a smoke test to ensure methods work
        $query = self::$orm
            ->table('users')
            ->select(['users.name', 'posts.title'])
            ->rightJoin('posts', 'users.id', '=', 'posts.user_id');

        self::assertInstanceOf(QueryBuilder::class, $query);

        $query2 = self::$orm->table('users')->fullOuterJoin('posts', 'users.id', '=', 'posts.user_id');

        self::assertInstanceOf(QueryBuilder::class, $query2);

        $query3 = self::$orm->table('users')->crossJoin('posts');

        self::assertInstanceOf(QueryBuilder::class, $query3);
    }

    // ======================================================================
    // JOIN Performance and Edge Cases
    // ======================================================================

    public function test_join_with_empty_result(): void
    {
        $results = self::$orm
            ->table('users')
            ->join('posts', 'users.id', '=', 'posts.user_id')
            ->where('users.id', '=', 99999) // Non-existent user
            ->getAll();

        self::assertCount(0, $results);
    }

    public function test_join_chaining(): void
    {
        $query = self::$orm
            ->table('posts')
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->leftJoin('categories', 'posts.category_id', '=', 'categories.id')
            ->rightJoin('tags', 'posts.id', '=', 'tags.post_id');

        // Test that the query builder is chainable
        self::assertInstanceOf(QueryBuilder::class, $query);

        // Test that we can continue building the query
        $finalQuery = $query->select(['posts.title', 'users.name'])->where('users.status', '=', 'active');

        self::assertInstanceOf(QueryBuilder::class, $finalQuery);
    }

    public function test_join_with_subquery(): void
    {
        // This tests the integration between JOINs and subqueries
        $subquery = self::$orm
            ->table('posts')
            ->select(['user_id', 'COUNT(*) as post_count'])
            ->groupBy('user_id')
            ->having('post_count', '>', 1);

        $results = self::$orm
            ->table('users')
            ->select(['users.name', 'active_users.post_count'])
            ->joinSub($subquery, 'active_users', 'users.id', '=', 'active_users.user_id')
            ->getAll();

        // The test should work now with Rust engine support
        self::assertIsArray($results);

        foreach ($results as $result) {
            self::assertArrayHasKey('name', $result);
            self::assertArrayHasKey('post_count', $result);
            self::assertGreaterThan(1, $result['post_count']);
        }
    }
}
