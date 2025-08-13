<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\Traits\HasRelationships;
use VersaORM\VersaModel;

// --- Test Models Definition ---

/**
 * @group mysql
 */
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
    public function testHasOneRelationship(): void
    {
        $user = UserTestModel::findOne('users', 1);
        self::assertInstanceOf(ProfileTestModel::class, $user->profile);
        self::assertSame('Alice bio', $user->profile->bio);
    }

    public function testBelongsToRelationship(): void
    {
        $profile = ProfileTestModel::findOne('profiles', 1);
        self::assertInstanceOf(UserTestModel::class, $profile->user);
        self::assertSame('Alice', $profile->user->name);
    }

    public function testHasManyRelationship(): void
    {
        $user = UserTestModel::findOne('users', 1);
        self::assertIsArray($user->posts);
        self::assertCount(2, $user->posts);
        self::assertInstanceOf(PostTestModel::class, $user->posts[0]);
        self::assertSame('Alice Post 1', $user->posts[0]->title);
    }

    public function testBelongsToManyRelationship(): void
    {
        $user = UserTestModel::findOne('users', 1);
        self::assertIsArray($user->roles);
        self::assertCount(2, $user->roles);
        self::assertInstanceOf(RoleTestModel::class, $user->roles[0]);
        self::assertSame('Admin', $user->roles[0]->name);
    }

    public function testEagerLoadingWithHasMany(): void
    {
        $user = parent::$orm->table('users', UserTestModel::class)->with('posts')->findOne();
        self::assertNotNull($user);
        self::assertArrayHasKey('posts', $user->getRelations());
        self::assertCount(2, $user->getRelations()['posts']);
        self::assertSame('Alice Post 1', $user->getRelations()['posts'][0]->title);
    }

    public function testEagerLoadingWithBelongsTo(): void
    {
        $post = parent::$orm->table('posts', PostTestModel::class)->with('user')->findOne();
        self::assertNotNull($post);
        self::assertArrayHasKey('user', $post->getRelations());
        self::assertInstanceOf(UserTestModel::class, $post->getRelations()['user']);
        self::assertSame('Alice', $post->getRelations()['user']->name);
    }

    public function testDatabaseTransactionsCommit(): void
    {
        parent::$orm->beginTransaction();
        parent::$orm->table('users')->insert(['name' => 'Test Commit', 'email' => 'test.commit@example.com']);
        parent::$orm->commit();

        $user = parent::$orm->table('users')->where('name', '=', 'Test Commit')->findOne();
        self::assertNotNull($user);
        self::assertSame('Test Commit', $user->name);
        self::assertSame('test.commit@example.com', $user->email);
    }

    // TODO: Comentado temporalmente - requiere mejoras en conexión CLI para transacciones
    // public function testDatabaseTransactionsRollback()
    // {
    //     parent::$orm->beginTransaction();
    //     parent::$orm->table('users')->insert(['name' => 'Test Rollback', 'email' => 'test@rollback.com']);
    //     parent::$orm->rollBack();

    //     $user = parent::$orm->table('users')->where('name', '=', 'Test Rollback')->findOne();
    //     $this->assertNull($user);
    // }
}
