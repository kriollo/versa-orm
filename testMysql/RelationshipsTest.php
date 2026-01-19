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
    public function test_has_one_relationship(): void
    {
        $user = UserTestModel::findOne('users', 1);
        static::assertInstanceOf(ProfileTestModel::class, $user->profile);
        static::assertSame('Alice bio', $user->profile->bio);
    }

    public function test_belongs_to_relationship(): void
    {
        $profile = ProfileTestModel::findOne('profiles', 1);
        static::assertInstanceOf(UserTestModel::class, $profile->user);
        static::assertSame('Alice', $profile->user->name);
    }

    public function test_has_many_relationship(): void
    {
        $user = UserTestModel::findOne('users', 1);
        static::assertIsArray($user->posts);
        static::assertCount(2, $user->posts);
        static::assertInstanceOf(PostTestModel::class, $user->posts[0]);
        static::assertSame('Alice Post 1', $user->posts[0]->title);
    }

    public function test_belongs_to_many_relationship(): void
    {
        $user = UserTestModel::findOne('users', 1);
        static::assertIsArray($user->roles);
        static::assertCount(2, $user->roles);
        static::assertInstanceOf(RoleTestModel::class, $user->roles[0]);
        static::assertSame('Admin', $user->roles[0]->name);
    }

    public function test_eager_loading_with_has_many(): void
    {
        $user = parent::$orm->table('users', UserTestModel::class)->with('posts')->findOne();
        static::assertNotNull($user);
        static::assertArrayHasKey('posts', $user->getRelations());
        static::assertCount(2, $user->getRelations()['posts']);
        static::assertSame('Alice Post 1', $user->getRelations()['posts'][0]->title);
    }

    public function test_eager_loading_with_belongs_to(): void
    {
        $post = parent::$orm->table('posts', PostTestModel::class)->with('user')->findOne();
        static::assertNotNull($post);
        static::assertArrayHasKey('user', $post->getRelations());
        static::assertInstanceOf(UserTestModel::class, $post->getRelations()['user']);
        static::assertSame('Alice', $post->getRelations()['user']->name);
    }

    public function test_attach_and_detach(): void
    {
        /** @var UserTestModel $user */
        $user = UserTestModel::findOne('users', 2); // Bob

        // Attach
        $user->roles()->attach(1); // Admin
        $attached = parent::$orm->table('role_user')->where('user_id', '=', 2)->where('role_id', '=', 1)->findOne();
        static::assertNotNull($attached);

        // Detach
        $user->roles()->detach(1);
        $detached = parent::$orm->table('role_user')->where('user_id', '=', 2)->where('role_id', '=', 1)->findOne();
        static::assertNull($detached);
    }

    public function test_sync(): void
    {
        /** @var UserTestModel $user */
        $user = UserTestModel::findOne('users', 2); // Bob

        // Buscar dinámicamente los IDs de los roles 'Viewer' y 'externo'
        $viewerRole = parent::$orm->table('roles')->where('name', '=', 'Viewer')->findOne();
        $externoRole = parent::$orm->table('roles')->where('name', '=', 'externo')->findOne();
        static::assertNotNull($viewerRole);
        static::assertNotNull($externoRole);
        $idViewer = $viewerRole->id;
        $idExterno = $externoRole->id;

        // elimino el rol 2
        $user->roles()->detach(2);

        // Estado inicial: attach individualmente
        $user->roles()->attach(1);
        $user->roles()->attach($idViewer);

        // Verificar estado inicial recargando
        $user = $user->fresh();
        static::assertCount(2, $user->roles);

        // Sync: debe dejar solo Viewer y externo
        $result = $user->roles()->sync([$idViewer, $idExterno]);
        static::assertArrayHasKey('attached', $result);
        static::assertArrayHasKey('detached', $result);

        // Recargar y verificar
        $user = $user->fresh();
        $roleIds = array_map(static fn($role) => $role->id, $user->roles);
        static::assertCount(2, $user->roles);
        static::assertContains($idViewer, $roleIds);
        static::assertContains($idExterno, $roleIds);
        static::assertNotContains(1, $roleIds);

        // atacho el rol 2
        $user->roles()->attach(2);
    }

    public function test_database_transactions_commit(): void
    {
        parent::$orm->beginTransaction();
        parent::$orm->table('users')->insert(['name' => 'Test Commit', 'email' => 'test.commit@example.com']);
        parent::$orm->commit();

        $user = parent::$orm->table('users')->where('name', '=', 'Test Commit')->findOne();
        static::assertNotNull($user);
        static::assertSame('Test Commit', $user->name);
        static::assertSame('test.commit@example.com', $user->email);
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
