<?php

declare(strict_types=1);

namespace VersaORM\Tests;

use PHPUnit\Framework\TestCase;
use VersaORM\Traits\HasRelationships;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

// --- Test Models Definition ---

class UserTestModel extends VersaModel
{
    use HasRelationships;
    protected string $table = 'users';

    public function profile()
    {
        return $this->hasOne(ProfileTestModel::class, 'user_id');
    }

    public function posts()
    {
        return $this->hasMany(PostTestModel::class, 'user_id');
    }

    public function roles()
    {
        return $this->belongsToMany(RoleTestModel::class, 'role_user', 'user_id', 'role_id');
    }
}

class ProfileTestModel extends VersaModel
{
    use HasRelationships;
    protected string $table = 'profiles';

    public function user()
    {
        return $this->belongsTo(UserTestModel::class, 'user_id');
    }
}

class PostTestModel extends VersaModel
{
    use HasRelationships;
    protected string $table = 'posts';

    public function user()
    {
        return $this->belongsTo(UserTestModel::class, 'user_id');
    }
}

class RoleTestModel extends VersaModel
{
    use HasRelationships;
    protected string $table = 'roles';

    public function users()
    {
        return $this->belongsToMany(UserTestModel::class, 'role_user', 'role_id', 'user_id');
    }
}


class RelationshipsTest extends TestCase
{
    private static ?VersaORM $orm = null;

    public static function setUpBeforeClass(): void
    {
        $config = [
            'driver'   => 'sqlite',
            'database' => ':memory:',
        ];
        self::$orm = new VersaORM($config);
        VersaModel::setORM(self::$orm);

        // Create schema
        self::$orm->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)');
        self::$orm->exec('CREATE TABLE profiles (id INTEGER PRIMARY KEY, user_id INTEGER, bio TEXT)');
        self::$orm->exec('CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT)');
        self::$orm->exec('CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT)');
        self::$orm->exec('CREATE TABLE role_user (user_id INTEGER, role_id INTEGER)');
    }

    protected function setUp(): void
    {
        // Clear and seed data for each test
        self::$orm->exec('DELETE FROM users');
        self::$orm->exec('DELETE FROM profiles');
        self::$orm->exec('DELETE FROM posts');
        self::$orm->exec('DELETE FROM roles');
        self::$orm->exec('DELETE FROM role_user');

        self::$orm->table('users')->insert(['id' => 1, 'name' => 'John Doe']);
        self::$orm->table('users')->insert(['id' => 2, 'name' => 'Jane Doe']);
        self::$orm->table('profiles')->insert(['id' => 1, 'user_id' => 1, 'bio' => 'Johns Bio']);
        self::$orm->table('posts')->insert(['id' => 1, 'user_id' => 1, 'title' => 'Post 1']);
        self::$orm->table('posts')->insert(['id' => 2, 'user_id' => 1, 'title' => 'Post 2']);
        self::$orm->table('roles')->insert(['id' => 1, 'name' => 'Admin']);
        self::$orm->table('roles')->insert(['id' => 2, 'name' => 'Editor']);
        self::$orm->table('role_user')->insert(['user_id' => 1, 'role_id' => 1]);
        self::$orm->table('role_user')->insert(['user_id' => 1, 'role_id' => 2]);
    }

    public function testHasOneRelationship()
    {
        $user = UserTestModel::findOne(1);
        $this->assertInstanceOf(ProfileTestModel::class, $user->profile);
        $this->assertEquals('Johns Bio', $user->profile->bio);
    }

    public function testBelongsToRelationship()
    {
        $profile = ProfileTestModel::findOne(1);
        $this->assertInstanceOf(UserTestModel::class, $profile->user);
        $this->assertEquals('John Doe', $profile->user->name);
    }

    public function testHasManyRelationship()
    {
        $user = UserTestModel::findOne(1);
        $this->assertIsArray($user->posts);
        $this->assertCount(2, $user->posts);
        $this->assertInstanceOf(PostTestModel::class, $user->posts[0]);
        $this->assertEquals('Post 1', $user->posts[0]->title);
    }

    public function testBelongsToManyRelationship()
    {
        $user = UserTestModel::findOne(1);
        $this->assertIsArray($user->roles);
        $this->assertCount(2, $user->roles);
        $this->assertInstanceOf(RoleTestModel::class, $user->roles[0]);
        $this->assertEquals('Admin', $user->roles[0]->name);
    }

    public function testEagerLoadingWithHasMany()
    {
        // Mocking is complex, so we'll test the outcome.
        // In a real scenario, you'd also use a query logger to assert query counts.
        $user = self::$orm->table('users')->with('posts')->findOne();

        // The 'relations' array should be populated without needing a lazy load call.
        $this->assertArrayHasKey('posts', $user->relations);
        $this->assertCount(2, $user->relations['posts']);
        $this->assertEquals('Post 1', $user->relations['posts'][0]->title);
    }

    public function testEagerLoadingWithBelongsTo()
    {
        $post = self::$orm->table('posts')->with('user')->findOne();

        $this->assertArrayHasKey('user', $post->relations);
        $this->assertInstanceOf(UserTestModel::class, $post->relations['user']);
        $this->assertEquals('John Doe', $post->relations['user']->name);
    }

    public function testDatabaseTransactionsCommit()
    {
        self::$orm->beginTransaction();
        self::$orm->table('users')->insert(['name' => 'Test Commit']);
        self::$orm->commit();

        $user = self::$orm->table('users')->where('name', '=', 'Test Commit')->findOne();
        $this->assertNotNull($user);
        $this->assertEquals('Test Commit', $user->name);
    }

    public function testDatabaseTransactionsRollback()
    {
        self::$orm->beginTransaction();
        self::$orm->table('users')->insert(['name' => 'Test Rollback']);
        self::$orm->rollBack();

        $user = self::$orm->table('users')->where('name', '=', 'Test Rollback')->findOne();
        $this->assertNull($user);
    }

    public static function tearDownAfterClass(): void
    {
        self::$orm->exec('DROP TABLE users');
        self::$orm->exec('DROP TABLE profiles');
        self::$orm->exec('DROP TABLE posts');
        self::$orm->exec('DROP TABLE roles');
        self::$orm->exec('DROP TABLE role_user');
        self::$orm = null;
    }
}
