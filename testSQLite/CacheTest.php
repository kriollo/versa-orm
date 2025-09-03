<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

require_once __DIR__ . '/TestCase.php';

/**
 * @group sqlite
 */
class CacheTest extends TestCase
{
    public function test_cache_enable(): void
    {
        $result = self::$orm->cache('enable');
        self::assertTrue($result === null || is_array($result), 'Cache enable should return null or array');
    }

    public function test_cache_disable(): void
    {
        $result = self::$orm->cache('disable');
        self::assertTrue($result === null || is_array($result), 'Cache disable should return null or array');
    }

    public function test_cache_clear(): void
    {
        $result = self::$orm->cache('clear');
        self::assertTrue($result === null || is_array($result), 'Cache clear should return null or array');
    }

    public function test_cache_status(): void
    {
        $result = self::$orm->cache('status');
        self::assertTrue($result === null || is_array($result), 'Cache status should return null or array');
    }

    public function test_cache_stats(): void
    {
        $result = self::$orm->cache('stats');
        self::assertTrue($result === null || is_array($result), 'Cache stats should return null or array');
    }

    public function test_cache_query_integration(): void
    {
        // Enable cache
        self::$orm->cache('enable');

        // Execute a query twice - second should be from cache
        $users1 = self::$orm->table('users')->where('status', '=', 'active')->getAll();
        $users2 = self::$orm->table('users')->where('status', '=', 'active')->getAll();

        self::assertCount(2, $users1);
        self::assertCount(2, $users2);
        self::assertEquals($users1, $users2);

        // Disable cache
        self::$orm->cache('disable');
    }

    public function test_cache_invalidation_after_insert(): void
    {
        // Enable cache
        self::$orm->cache('enable');

        // Get initial count
        $initialCount = self::$orm->table('users')->count();

        // Insert new user
        self::$orm->table('users')->insert(['name' => 'Cache Test', 'email' => 'cache@test.com', 'status' => 'active']);

        // Count should be updated (cache invalidated)
        $newCount = self::$orm->table('users')->count();
        self::assertSame($initialCount + 1, $newCount);

        // Disable cache
        self::$orm->cache('disable');
    }

    public function test_cache_invalidation_after_update(): void
    {
        // Enable cache
        self::$orm->cache('enable');

        // Get user
        $user = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        $originalStatus = $user->status;

        // Update user
        self::$orm->table('users')->where('email', '=', 'alice@example.com')->update(['status' => 'updated']);

        // Get user again - should reflect update
        $updatedUser = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        self::assertSame('updated', $updatedUser->status);
        self::assertNotSame($originalStatus, $updatedUser->status);

        // Disable cache
        self::$orm->cache('disable');
    }

    public function test_cache_invalidation_after_delete(): void
    {
        // Enable cache
        self::$orm->cache('enable');

        // Insert a test user
        self::$orm
            ->table('users')
            ->insert(['name' => 'Delete Test', 'email' => 'delete@test.com', 'status' => 'active']);

        // Verify user exists
        $user = self::$orm->table('users')->where('email', '=', 'delete@test.com')->findOne();
        self::assertNotNull($user);

        // Delete user
        self::$orm->table('users')->where('email', '=', 'delete@test.com')->delete();

        // Verify user is gone (cache invalidated)
        $deletedUser = self::$orm->table('users')->where('email', '=', 'delete@test.com')->findOne();
        self::assertNull($deletedUser);

        // Disable cache
        self::$orm->cache('disable');
    }

    public function test_invalid_cache_action(): void
    {
        $this->expectException(\VersaORM\VersaORMException::class);
        self::$orm->cache('invalid_action');
    }

    public function test_cache_invalidate_without_parameters(): void
    {
        $result = self::$orm->cache('invalidate');
        self::assertTrue($result === null || is_array($result), 'Cache invalidate should return null or array');
    }
}
