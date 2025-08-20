<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\Traits\HasRelationships;
use VersaORM\VersaModel;

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
    public function testAttachAndDetach(): void
    {
        /** @var UserTestModel $user */
        $user = UserTestModel::findOne('users', 2); // Bob

        // Attach
        $user->roles()->attach(1); // Admin
        $attached = parent::$orm->table('role_user')->where('user_id', '=', 2)->where('role_id', '=', 1)->findOne();
        self::assertNotNull($attached);

        // Detach
        $user->roles()->detach(1);
        $detached = parent::$orm->table('role_user')->where('user_id', '=', 2)->where('role_id', '=', 1)->findOne();
        self::assertNull($detached);
    }

    public function testSync(): void
    {
        /** @var UserTestModel $user */
        $user = UserTestModel::findOne('users', 2); // Bob

        // Buscar dinámicamente los IDs de los roles 'Viewer' y 'externo'
        $viewerRole = parent::$orm->table('roles')->where('name', '=', 'Viewer')->findOne();
        $externoRole = parent::$orm->table('roles')->where('name', '=', 'externo')->findOne();
        self::assertNotNull($viewerRole);
        self::assertNotNull($externoRole);
        $idViewer = $viewerRole->id;
        $idExterno = $externoRole->id;

        //elimino el rol 2
        $user->roles()->detach(2);

        // Estado inicial: attach individualmente
        $user->roles()->attach(1);
        $user->roles()->attach($idViewer);

        // Verificar estado inicial recargando
        $user = $user->fresh();
        self::assertCount(2, $user->roles);

        // Sync: debe dejar solo Viewer y externo
        $result = $user->roles()->sync([$idViewer, $idExterno]);
        self::assertArrayHasKey('attached', $result);
        self::assertArrayHasKey('detached', $result);

        // Recargar y verificar
        $user = $user->fresh();
        $roleIds = array_map(fn ($role) => $role->id, $user->roles);
        self::assertCount(2, $user->roles);
        self::assertContains($idViewer, $roleIds);
        self::assertContains($idExterno, $roleIds);
        self::assertNotContains(1, $roleIds);

        // atacho el rol 2
        $user->roles()->attach(2);
    }

    public function testFresh(): void
    {
        $user = UserTestModel::findOne('users', 2);
        $user->roles()->attach(3);
        $user = $user->fresh();
        $roleIds = array_map(fn ($role) => $role->id, $user->roles);
        self::assertContains(3, $roleIds);
    }

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
