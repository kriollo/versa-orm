<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * Tests exhaustivos para relaciones avanzadas y edge cases.
 *
 * @group postgresql
 * @group relations
 * @group advanced
 */
class RelationshipsAdvancedTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Crear estructura adicional para tests de relaciones complejas
        self::$orm->schemaCreate('countries', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'name', 'type' => 'VARCHAR(100)'],
            ['name' => 'code', 'type' => 'VARCHAR(3)'],
        ]);

        self::$orm->schemaCreate('cities', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'name', 'type' => 'VARCHAR(100)'],
            ['name' => 'country_id', 'type' => 'INTEGER'],
        ]);

        self::$orm->schemaCreate('companies', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'name', 'type' => 'VARCHAR(100)'],
            ['name' => 'city_id', 'type' => 'INTEGER'],
        ]);

        self::$orm->schemaCreate('employees', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'name', 'type' => 'VARCHAR(100)'],
            ['name' => 'company_id', 'type' => 'INTEGER'],
            ['name' => 'manager_id', 'type' => 'INTEGER', 'nullable' => true],
        ]);

        self::$orm->schemaCreate('tags', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'name', 'type' => 'VARCHAR(50)'],
        ]);

        self::$orm->schemaCreate(
            'post_tag',
            [
                ['name' => 'post_id', 'type' => 'INTEGER'],
                ['name' => 'tag_id', 'type' => 'INTEGER'],
                ['name' => 'created_at', 'type' => 'TIMESTAMP', 'nullable' => true],
            ],
            ['primary_key' => ['post_id', 'tag_id']],
        );
    }

    protected function tearDown(): void
    {
        self::$orm->schemaDrop('post_tag');
        self::$orm->schemaDrop('tags');
        self::$orm->schemaDrop('employees');
        self::$orm->schemaDrop('companies');
        self::$orm->schemaDrop('cities');
        self::$orm->schemaDrop('countries');

        parent::tearDown();
    }

    /**
     * Test: Relación hasMany con cero registros relacionados.
     */
    public function test_has_many_with_zero_records(): void
    {
        // Usuario sin posts
        $user = VersaModel::dispense('users');
        $user->name = 'No Posts User';
        $user->email = 'noposts@example.com';
        $user->store();

        $posts = self::$orm->table('posts')->where('user_id', '=', $user->id)->get();

        static::assertIsArray($posts);
        static::assertEmpty($posts);
        static::assertCount(0, $posts);
    }

    /**
     * Test: Relación hasMany con múltiples niveles (más de 100 registros).
     */
    public function test_has_many_with_large_dataset(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'Prolific Writer';
        $user->email = 'writer@example.com';
        $user->store();

        // Crear 150 posts
        for ($i = 1; $i <= 150; $i++) {
            $post = VersaModel::dispense('posts');
            $post->user_id = $user->id;
            $post->title = "Post {$i}";
            $post->content = "Content {$i}";
            $post->store();
        }

        $posts = self::$orm->table('posts')->where('user_id', '=', $user->id)->get();

        static::assertCount(150, $posts);

        // Verificar paginación
        $firstPage = self::$orm->table('posts')->where('user_id', '=', $user->id)->limit(50)->get();

        static::assertCount(50, $firstPage);
    }

    /**
     * Test: Relación belongsTo con foreign key NULL.
     */
    public function test_belongs_to_with_null_foreign_key(): void
    {
        // Post sin usuario
        $post = VersaModel::dispense('posts');
        $post->user_id = null;
        $post->title = 'Orphan Post';
        $post->content = 'No owner';
        $post->store();

        static::assertNull($post->user_id);

        // Intentar obtener el usuario (debería ser null o vacío)
        $user = self::$orm->table('users')->where('id', '=', $post->user_id)->first();

        static::assertNull($user);
    }

    /**
     * Test: Relación belongsToMany con tabla pivot vacía.
     */
    public function test_belongs_to_many_empty_pivot(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'No Roles User';
        $user->email = 'noroles@example.com';
        $user->store();

        // No asignar roles
        $roles = self::$orm
            ->table('roles')
            ->join('role_user', 'roles.id', '=', 'role_user.role_id')
            ->where('role_user.user_id', '=', $user->id)
            ->select(['roles.*'])
            ->get();

        static::assertIsArray($roles);
        static::assertEmpty($roles);
    }

    /**
     * Test: Relación belongsToMany con múltiples registros en pivot.
     */
    public function test_belongs_to_many_multiple_relations(): void
    {
        $user = VersaModel::load('users', 1); // Alice del seed

        // Verificar roles existentes
        $roles = self::$orm
            ->table('roles')
            ->join('role_user', 'roles.id', '=', 'role_user.role_id')
            ->where('role_user.user_id', '=', $user->id)
            ->select(['roles.*'])
            ->get();

        static::assertGreaterThanOrEqual(2, count($roles));

        // Agregar más roles
        $newRole1 = VersaModel::dispense('roles');
        $newRole1->name = 'Extra Role 1';
        $newRole1->store();

        $newRole2 = VersaModel::dispense('roles');
        $newRole2->name = 'Extra Role 2';
        $newRole2->store();

        self::$orm->table('role_user')->insert(['user_id' => $user->id, 'role_id' => $newRole1->id]);
        self::$orm->table('role_user')->insert(['user_id' => $user->id, 'role_id' => $newRole2->id]);

        // Verificar
        $allRoles = self::$orm
            ->table('roles')
            ->join('role_user', 'roles.id', '=', 'role_user.role_id')
            ->where('role_user.user_id', '=', $user->id)
            ->select(['roles.*'])
            ->get();

        static::assertGreaterThanOrEqual(4, count($allRoles));
    }

    /**
     * Test: Relación con tabla pivot que tiene columnas adicionales.
     */
    public function test_pivot_table_with_extra_columns(): void
    {
        $post = VersaModel::load('posts', 1);
        $tag = VersaModel::dispense('tags');
        $tag->name = 'Important';
        $tag->store();

        // Insertar en pivot con timestamp
        self::$orm
            ->table('post_tag')
            ->insert([
                'post_id' => $post->id,
                'tag_id' => $tag->id,
                'created_at' => date('Y-m-d H:i:s'),
            ]);

        // Verificar que se guardó con la columna adicional
        $pivot = self::$orm
            ->table('post_tag')
            ->where('post_id', '=', $post->id)
            ->where('tag_id', '=', $tag->id)
            ->first();

        static::assertNotNull($pivot);
        // first() returns VersaModel - access via export() to get array
        $pivotData = $pivot instanceof \VersaORM\VersaModel ? $pivot->export() : $pivot;
        static::assertIsArray($pivotData);
        static::assertArrayHasKey('created_at', $pivotData);
        static::assertNotNull($pivotData['created_at']);
    }

    /**
     * Test: Relaciones anidadas (through relationships simuladas).
     */
    public function test_nested_relationships_manual(): void
    {
        // Crear estructura: Country -> City -> Company -> Employees
        $country = VersaModel::dispense('countries');
        $country->name = 'USA';
        $country->code = 'US';
        $country->store();

        $city = VersaModel::dispense('cities');
        $city->name = 'New York';
        $city->country_id = $country->id;
        $city->store();

        $company = VersaModel::dispense('companies');
        $company->name = 'Tech Corp';
        $company->city_id = $city->id;
        $company->store();

        $employee = VersaModel::dispense('employees');
        $employee->name = 'John Doe';
        $employee->company_id = $company->id;
        $employee->store();

        // Obtener empleados de un país (3 joins)
        $employees = self::$orm
            ->table('employees')
            ->join('companies', 'employees.company_id', '=', 'companies.id')
            ->join('cities', 'companies.city_id', '=', 'cities.id')
            ->join('countries', 'cities.country_id', '=', 'countries.id')
            ->where('countries.id', '=', $country->id)
            ->select(['employees.*', 'countries.name as country_name'])
            ->get();

        static::assertNotEmpty($employees);
        static::assertSame('USA', $employees[0]['country_name']);
    }

    /**
     * Test: Self-referencing relationship (empleados con manager).
     */
    public function test_self_referencing_relationship(): void
    {
        $company = VersaModel::dispense('companies');
        $company->name = 'Corp Inc';
        $company->city_id = 1;
        $company->store();

        // Manager
        $manager = VersaModel::dispense('employees');
        $manager->name = 'Boss';
        $manager->company_id = $company->id;
        $manager->manager_id = null;
        $manager->store();

        // Empleados bajo el manager
        $employee1 = VersaModel::dispense('employees');
        $employee1->name = 'Employee 1';
        $employee1->company_id = $company->id;
        $employee1->manager_id = $manager->id;
        $employee1->store();

        $employee2 = VersaModel::dispense('employees');
        $employee2->name = 'Employee 2';
        $employee2->company_id = $company->id;
        $employee2->manager_id = $manager->id;
        $employee2->store();

        // Obtener empleados de un manager
        $subordinates = self::$orm->table('employees')->where('manager_id', '=', $manager->id)->get();

        static::assertCount(2, $subordinates);

        // Obtener manager de un empleado
        $employeeWithManager = VersaModel::load('employees', $employee1->id);
        $loadedManager = VersaModel::load('employees', $employeeWithManager->manager_id);

        static::assertSame('Boss', $loadedManager->name);
    }

    /**
     * Test: Eliminación en cascada simulada.
     */
    public function test_cascade_delete_simulation(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'User to Delete';
        $user->email = 'delete@example.com';
        $user->store();

        $userId = $user->id;

        // Crear posts para el usuario
        for ($i = 1; $i <= 5; $i++) {
            $post = VersaModel::dispense('posts');
            $post->user_id = $userId;
            $post->title = "Post {$i}";
            $post->content = 'Content';
            $post->store();
        }

        // Verificar posts existen
        $posts = self::$orm->table('posts')->where('user_id', '=', $userId)->get();
        static::assertCount(5, $posts);

        // Eliminar manualmente los posts primero (simulando cascada)
        self::$orm->table('posts')->where('user_id', '=', $userId)->delete();

        // Verificar posts eliminados
        $postsAfter = self::$orm->table('posts')->where('user_id', '=', $userId)->get();
        static::assertEmpty($postsAfter);

        // Eliminar usuario
        $user->trash();

        // Verificar usuario eliminado
        $deletedUser = VersaModel::load('users', $userId);
        static::assertNull($deletedUser);
    }

    /**
     * Test: Actualización de foreign key.
     */
    public function test_foreign_key_update(): void
    {
        $user1 = VersaModel::load('users', 1);
        $user2 = VersaModel::load('users', 2);

        $post = VersaModel::dispense('posts');
        $post->user_id = $user1->id;
        $post->title = 'Test Post';
        $post->content = 'Content';
        $post->store();

        static::assertSame($user1->id, $post->user_id);

        // Cambiar owner del post
        $post->user_id = $user2->id;
        $post->store();

        // Verificar cambio
        $reloaded = VersaModel::load('posts', $post->id);
        static::assertSame($user2->id, $reloaded->user_id);
    }

    /**
     * Test: Múltiples belongsToMany en un mismo modelo.
     */
    public function test_multiple_many_to_many_on_same_model(): void
    {
        $post = VersaModel::load('posts', 1);

        // Crear múltiples tags
        $tag1 = VersaModel::dispense('tags');
        $tag1->name = 'PHP';
        $tag1->store();

        $tag2 = VersaModel::dispense('tags');
        $tag2->name = 'Testing';
        $tag2->store();

        $tag3 = VersaModel::dispense('tags');
        $tag3->name = 'PostgreSQL';
        $tag3->store();

        // Asociar todos los tags
        self::$orm->table('post_tag')->insert(['post_id' => $post->id, 'tag_id' => $tag1->id]);
        self::$orm->table('post_tag')->insert(['post_id' => $post->id, 'tag_id' => $tag2->id]);
        self::$orm->table('post_tag')->insert(['post_id' => $post->id, 'tag_id' => $tag3->id]);

        // Obtener tags del post
        $tags = self::$orm
            ->table('tags')
            ->join('post_tag', 'tags.id', '=', 'post_tag.tag_id')
            ->where('post_tag.post_id', '=', $post->id)
            ->select(['tags.*'])
            ->get();

        static::assertCount(3, $tags);

        // Obtener posts de un tag
        $posts = self::$orm
            ->table('posts')
            ->join('post_tag', 'posts.id', '=', 'post_tag.post_id')
            ->where('post_tag.tag_id', '=', $tag1->id)
            ->select(['posts.*'])
            ->get();

        static::assertGreaterThanOrEqual(1, count($posts));
    }

    /**
     * Test: Relación con condiciones WHERE complejas.
     */
    public function test_relationship_with_complex_where_conditions(): void
    {
        $user = VersaModel::load('users', 1);

        // Posts del usuario creados en un rango de fechas
        $post1 = VersaModel::dispense('posts');
        $post1->user_id = $user->id;
        $post1->title = 'Old Post';
        $post1->content = 'Content';
        $post1->published_at = '2020-01-01 00:00:00';
        $post1->store();

        $post2 = VersaModel::dispense('posts');
        $post2->user_id = $user->id;
        $post2->title = 'Recent Post';
        $post2->content = 'Content';
        $post2->published_at = '2023-01-01 00:00:00';
        $post2->store();

        // Obtener solo posts recientes
        $recentPosts = self::$orm
            ->table('posts')
            ->where('user_id', '=', $user->id)
            ->where('published_at', '>', '2022-01-01')
            ->get();

        static::assertGreaterThanOrEqual(1, count($recentPosts));

        foreach ($recentPosts as $post) {
            // published_at might be DateTime object or string
            $publishedAt = $post['published_at'];
            if ($publishedAt instanceof \DateTime) {
                $timestamp = $publishedAt->getTimestamp();
            } else {
                $timestamp = strtotime((string) $publishedAt);
            }
            static::assertGreaterThan(strtotime('2022-01-01'), $timestamp);
        }
    }

    /**
     * Test: Verificar integridad referencial con datos inválidos.
     */
    public function test_referential_integrity_with_invalid_foreign_key(): void
    {
        $this->expectException(\Throwable::class);

        // Intentar crear post con user_id inexistente
        $post = VersaModel::dispense('posts');
        $post->user_id = 99999; // ID que no existe
        $post->title = 'Invalid Post';
        $post->content = 'Should fail';
        $post->store(); // Debería fallar por constraint de foreign key
    }
}
