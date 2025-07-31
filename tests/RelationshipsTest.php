<?php

declare(strict_types=1);

namespace VersaORM\Tests;

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
    public function testHasOneRelationship()
    {
        $user = UserTestModel::findOne('users', 1);
        $this->assertInstanceOf(ProfileTestModel::class, $user->profile);
        $this->assertEquals('Alice bio', $user->profile->bio);
    }

    public function testBelongsToRelationship()
    {
        $profile = ProfileTestModel::findOne('profiles', 1);
        $this->assertInstanceOf(UserTestModel::class, $profile->user);
        $this->assertEquals('Alice', $profile->user->name);
    }

    public function testHasManyRelationship()
    {
        $user = UserTestModel::findOne('users', 1);
        $this->assertIsArray($user->posts);
        $this->assertCount(2, $user->posts);
        $this->assertInstanceOf(PostTestModel::class, $user->posts[0]);
        $this->assertEquals('Alice Post 1', $user->posts[0]->title);
    }

    public function testBelongsToManyRelationship()
    {
        $user = UserTestModel::findOne('users', 1);
        $this->assertIsArray($user->roles);
        $this->assertCount(2, $user->roles);
        $this->assertInstanceOf(RoleTestModel::class, $user->roles[0]);
        $this->assertEquals('Admin', $user->roles[0]->name);
    }

    public function testEagerLoadingWithHasMany()
    {
        $user = parent::$orm->table('users', UserTestModel::class)->with('posts')->findOne();
        $this->assertNotNull($user);
        $this->assertArrayHasKey('posts', $user->getRelations());
        $this->assertCount(2, $user->getRelations()['posts']);
        $this->assertEquals('Post 1', $user->getRelations()['posts'][0]->title);
    }

    public function testEagerLoadingWithBelongsTo()
    {
        $post = parent::$orm->table('posts', PostTestModel::class)->with('user')->findOne();
        $this->assertNotNull($post);
        $this->assertArrayHasKey('user', $post->getRelations());
        $this->assertInstanceOf(UserTestModel::class, $post->getRelations()['user']);
        $this->assertEquals('John Doe', $post->getRelations()['user']->name);
    }

    public function testDatabaseTransactionsCommit()
    {
        parent::$orm->beginTransaction();
        parent::$orm->table('users')->insert(['name' => 'Test Commit']);
        parent::$orm->commit();

        $user = parent::$orm->table('users')->where('name', '=', 'Test Commit')->findOne();
        $this->assertNotNull($user);
        $this->assertEquals('Test Commit', $user->name);
    }

    public function testDatabaseTransactionsRollback()
    {
        parent::$orm->beginTransaction();
        parent::$orm->table('users')->insert(['name' => 'Test Rollback', 'email' => 'test@rollback.com']);
        parent::$orm->rollBack();

        $user = parent::$orm->table('users')->where('name', '=', 'Test Rollback')->findOne();
        $this->assertNull($user);
    }
}
