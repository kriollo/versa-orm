<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

use function async;
use function await;

require_once __DIR__ . '/TestCase.php';

/**
 * Modelo de prueba para usuarios con fillable definido (para Pokio tests).
 */
class PokioTestUserModel extends VersaModel
{
    protected string $table = 'users';

    protected array $fillable = ['name', 'email', 'status'];

    protected array $guarded = [];
}

/**
 * Modelo de prueba para posts con fillable definido (para Pokio tests).
 */
class PokioTestPostModel extends VersaModel
{
    protected string $table = 'posts';

    protected array $fillable = ['user_id', 'title', 'content', 'published_at'];

    protected array $guarded = [];
}

/**
 * Test para verificar operaciones asíncronas con Pokio en PostgreSQL.
 *
 * @group postgresql
 * @group pokio
 */
class PokioAsyncTest extends TestCase
{
    /**
     * Test básico: guardar un modelo de manera asíncrona.
     */
    public function test_async_store_single_model(): void
    {
        // Crear una promesa que guarda un usuario de manera asíncrona
        $promise = async(static function () {
            $user = VersaModel::dispense('users');
            $user->name = 'Async User';
            $user->email = 'async@example.com';
            $user->status = 'active';
            $user->store();

            return $user;
        });

        // Esperar a que la promesa se resuelva
        $savedUser = await($promise);

        // Verificar que el usuario se guardó correctamente
        static::assertNotNull($savedUser->id, 'El ID debe estar asignado después de guardar');
        static::assertSame('Async User', $savedUser->name);
        static::assertSame('async@example.com', $savedUser->email);

        // Verificar que el usuario existe en la base de datos
        $dbUser = VersaModel::load('users', $savedUser->id);
        static::assertNotNull($dbUser);
        static::assertSame('Async User', $dbUser->name);
        static::assertSame('async@example.com', $dbUser->email);
    }

    /**
     * Test: guardar múltiples modelos de manera asíncrona en paralelo.
     */
    public function test_async_store_multiple_models_parallel(): void
    {
        // Crear varias promesas que guardan usuarios de manera asíncrona
        $promises = [
            async(static function () {
                $user = VersaModel::dispense('users');
                $user->name = 'Async User 1';
                $user->email = 'async1@example.com';
                $user->status = 'active';
                $user->store();

                return $user;
            }),
            async(static function () {
                $user = VersaModel::dispense('users');
                $user->name = 'Async User 2';
                $user->email = 'async2@example.com';
                $user->status = 'inactive';
                $user->store();

                return $user;
            }),
            async(static function () {
                $user = VersaModel::dispense('users');
                $user->name = 'Async User 3';
                $user->email = 'async3@example.com';
                $user->status = 'active';
                $user->store();

                return $user;
            }),
        ];

        // Esperar a que todas las promesas se resuelvan
        $savedUsers = await($promises);

        // Verificar que se guardaron 3 usuarios
        static::assertCount(3, $savedUsers);

        // Verificar cada usuario
        foreach ($savedUsers as $index => $user) {
            $userNumber = $index + 1;
            static::assertNotNull($user->id, "El usuario {$userNumber} debe tener un ID");
            static::assertSame("Async User {$userNumber}", $user->name);
            static::assertSame("async{$userNumber}@example.com", $user->email);

            // Verificar que existen en la base de datos
            $dbUser = VersaModel::load('users', $user->id);
            static::assertNotNull($dbUser);
            static::assertSame($user->name, $dbUser->name);
        }
    }

    /**
     * Test: actualizar un modelo de manera asíncrona.
     */
    public function test_async_update_model(): void
    {
        // Primero, crear un usuario de manera síncrona
        $user = VersaModel::dispense('users');
        $user->name = 'Original Name';
        $user->email = 'original@example.com';
        $user->status = 'active';
        $user->store();

        $userId = $user->id;

        // Actualizar el usuario de manera asíncrona
        $promise = async(static function () use ($userId) {
            $user = VersaModel::load('users', $userId);
            $user->name = 'Updated Async Name';
            $user->status = 'inactive';
            $user->store();

            return $user;
        });

        // Esperar a que la actualización se complete
        $updatedUser = await($promise);

        // Verificar la actualización
        static::assertSame('Updated Async Name', $updatedUser->name);
        static::assertSame('inactive', $updatedUser->status);

        // Verificar en la base de datos
        $dbUser = VersaModel::load('users', $userId);
        static::assertSame('Updated Async Name', $dbUser->name);
        static::assertSame('inactive', $dbUser->status);
    }

    /**
     * Test: eliminar un modelo de manera asíncrona.
     */
    public function test_async_trash_model(): void
    {
        // Crear un usuario para eliminar
        $user = VersaModel::dispense('users');
        $user->name = 'To Be Deleted';
        $user->email = 'delete@example.com';
        $user->status = 'active';
        $user->store();

        $userId = $user->id;
        static::assertNotNull($userId);

        // Eliminar el usuario de manera asíncrona
        $promise = async(static function () use ($userId) {
            $user = VersaModel::load('users', $userId);
            $user->trash();

            return true;
        });

        // Esperar a que la eliminación se complete
        $result = await($promise);

        static::assertTrue($result);

        // Verificar que el usuario ya no existe
        $deletedUser = VersaModel::load('users', $userId);
        static::assertNull($deletedUser);
    }

    /**
     * Test: consultas asíncronas con findAll.
     */
    public function test_async_find_all_models(): void
    {
        // Crear algunos usuarios de manera síncrona
        $user1 = VersaModel::dispense('users');
        $user1->name = 'Query User 1';
        $user1->email = 'query1@example.com';
        $user1->status = 'pending';
        $user1->store();

        $user2 = VersaModel::dispense('users');
        $user2->name = 'Query User 2';
        $user2->email = 'query2@example.com';
        $user2->status = 'pending';
        $user2->store();

        // Consultar usuarios de manera asíncrona
        $promise = async(static fn() => VersaModel::findAll('users', 'status = ?', ['pending']));

        // Esperar el resultado
        $users = await($promise);

        // Verificar que se encontraron los usuarios
        static::assertGreaterThanOrEqual(2, count($users));

        // Verificar que todos tienen el status correcto
        foreach ($users as $user) {
            static::assertSame('pending', $user->status);
        }
    }

    /**
     * Test: operaciones mixtas con then, catch y finally.
     */
    public function test_async_with_promise_methods(): void
    {
        $finallyExecuted = false;

        $promise = async(static function () {
            $user = VersaModel::dispense('users');
            $user->name = 'Promise Methods User';
            $user->email = 'promise@example.com';
            $user->status = 'active';
            $user->store();

            return $user;
        })
            ->then(static fn($user) => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ])
            ->finally(static function () use (&$finallyExecuted) {
                $finallyExecuted = true;
            });

        // Esperar el resultado
        $result = await($promise);

        // Verificar el resultado transformado
        static::assertIsArray($result);
        static::assertArrayHasKey('id', $result);
        static::assertArrayHasKey('name', $result);
        static::assertArrayHasKey('email', $result);
        static::assertSame('Promise Methods User', $result['name']);
        static::assertSame('promise@example.com', $result['email']);

        // Verificar que finally se ejecutó
        static::assertTrue($finallyExecuted);
    }

    /**
     * Test: manejo de errores con catch.
     */
    public function test_async_error_handling_with_catch(): void
    {
        $promise = async(static function () {
            // Intentar crear un usuario con email duplicado (debería fallar por constraint unique)
            $user1 = VersaModel::dispense('users');
            $user1->name = 'Duplicate User 1';
            $user1->email = 'duplicate@example.com';
            $user1->store();

            $user2 = VersaModel::dispense('users');
            $user2->name = 'Duplicate User 2';
            $user2->email = 'duplicate@example.com'; // Email duplicado
            $user2->store(); // Esto debería lanzar una excepción

            return $user2;
        })->catch(static fn(\Throwable $e) => 'Error capturado: Email duplicado');

        // Esperar el resultado
        $result = await($promise);

        // Verificar que el error fue capturado
        static::assertIsString($result);
        static::assertStringContainsString('Error capturado', $result);
    }

    /**
     * Test: operaciones de lectura y escritura combinadas de manera asíncrona.
     */
    public function test_async_read_write_combined(): void
    {
        // Crear un post de manera asíncrona vinculado a un usuario existente
        $promise = async(static function () {
            // Leer el primer usuario (Alice, creado en el seed)
            $user = VersaModel::load('users', 1);
            static::assertNotNull($user);

            // Crear un post para ese usuario
            $post = VersaModel::dispense('posts');
            $post->user_id = $user->id;
            $post->title = 'Async Post Title';
            $post->content = 'This post was created asynchronously using Pokio';
            $post->store();

            return $post;
        });

        // Esperar el resultado
        $savedPost = await($promise);

        // Verificar el post guardado
        static::assertNotNull($savedPost->id);
        static::assertSame('Async Post Title', $savedPost->title);
        static::assertSame(1, $savedPost->user_id);

        // Verificar en la base de datos
        $dbPost = VersaModel::load('posts', $savedPost->id);
        static::assertNotNull($dbPost);
        static::assertSame('Async Post Title', $dbPost->title);
    }

    /**
     * Test: pasar instancia del modelo por use y guardar de manera asíncrona.
     */
    public function test_async_store_model_passed_by_use(): void
    {
        // Crear la instancia del modelo primero
        $user = VersaModel::dispense('users');
        $user->name = 'User Passed By Use';
        $user->email = 'passed@example.com';
        $user->status = 'active';

        // Pasar la instancia mediante use y guardar de manera asíncrona
        $promise = async(static function () use ($user) {
            $user->store();

            return $user;
        });

        // Esperar el resultado
        $savedUser = await($promise);

        // Verificar que se guardó correctamente
        static::assertNotNull($savedUser->id);
        static::assertSame('User Passed By Use', $savedUser->name);
        static::assertSame('passed@example.com', $savedUser->email);

        // Verificar en la base de datos
        $dbUser = VersaModel::load('users', $savedUser->id);
        static::assertNotNull($dbUser);
        static::assertSame('User Passed By Use', $dbUser->name);
    }

    /**
     * Test: usar asignación directa y guardar de manera asíncrona pasando la instancia por use.
     */
    public function test_async_store_with_fill_passed_by_use(): void
    {
        // Crear la instancia del modelo
        $user = VersaModel::dispense('users');
        $user->name = 'User With Fill';
        $user->email = 'fill@example.com';
        $user->status = 'active';

        // Pasar la instancia mediante use y guardar de manera asíncrona
        $promise = async(static function () use ($user) {
            $user->store();

            return $user;
        });

        // Esperar el resultado
        $savedUser = await($promise);

        // Verificar que se guardó correctamente
        static::assertNotNull($savedUser->id);
        static::assertSame('User With Fill', $savedUser->name);
        static::assertSame('fill@example.com', $savedUser->email);
        static::assertSame('active', $savedUser->status);

        // Verificar en la base de datos
        $dbUser = VersaModel::load('users', $savedUser->id);
        static::assertNotNull($dbUser);
        static::assertSame('User With Fill', $dbUser->name);
        static::assertSame('fill@example.com', $dbUser->email);
    }

    /**
     * Test: múltiples instancias guardadas en paralelo pasadas por use.
     */
    public function test_async_multiple_models_with_fill_parallel(): void
    {
        // Crear múltiples instancias
        $user1 = VersaModel::dispense('users');
        $user1->name = 'Parallel User 1';
        $user1->email = 'parallel1@example.com';
        $user1->status = 'active';

        $user2 = VersaModel::dispense('users');
        $user2->name = 'Parallel User 2';
        $user2->email = 'parallel2@example.com';
        $user2->status = 'inactive';

        $user3 = VersaModel::dispense('users');
        $user3->name = 'Parallel User 3';
        $user3->email = 'parallel3@example.com';
        $user3->status = 'active';

        // Crear promesas para cada usuario
        $promises = [
            async(static function () use ($user1) {
                $user1->store();

                return $user1;
            }),
            async(static function () use ($user2) {
                $user2->store();

                return $user2;
            }),
            async(static function () use ($user3) {
                $user3->store();

                return $user3;
            }),
        ];

        // Esperar a que todas se resuelvan
        $savedUsers = await($promises);

        // Verificar que se guardaron todos
        static::assertCount(3, $savedUsers);

        // Verificar cada usuario
        static::assertNotNull($savedUsers[0]->id);
        static::assertSame('Parallel User 1', $savedUsers[0]->name);

        static::assertNotNull($savedUsers[1]->id);
        static::assertSame('Parallel User 2', $savedUsers[1]->name);

        static::assertNotNull($savedUsers[2]->id);
        static::assertSame('Parallel User 3', $savedUsers[2]->name);

        // Verificar en la base de datos
        foreach ($savedUsers as $user) {
            $dbUser = VersaModel::load('users', $user->id);
            static::assertNotNull($dbUser);
            static::assertSame($user->name, $dbUser->name);
        }
    }

    /**
     * Test: actualizar modelo existente de manera asíncrona con datos pasados por use.
     */
    public function test_async_update_with_fill_passed_by_use(): void
    {
        // Crear un usuario primero
        $user = VersaModel::dispense('users');
        $user->name = 'Original User';
        $user->email = 'original.fill@example.com';
        $user->status = 'active';
        $user->store();

        $userId = $user->id;
        static::assertNotNull($userId);

        // Cargar el usuario para actualizarlo
        $userToUpdate = VersaModel::load('users', $userId);

        // Actualizar de manera asíncrona
        $promise = async(static function () use ($userToUpdate) {
            $userToUpdate->name = 'Updated With Fill';
            $userToUpdate->status = 'inactive';
            $userToUpdate->store();

            return $userToUpdate;
        });

        // Esperar el resultado
        $updatedUser = await($promise);

        // Verificar la actualización
        static::assertSame('Updated With Fill', $updatedUser->name);
        static::assertSame('inactive', $updatedUser->status);
        static::assertSame('original.fill@example.com', $updatedUser->email); // El email no cambió

        // Verificar en la base de datos
        $dbUser = VersaModel::load('users', $userId);
        static::assertSame('Updated With Fill', $dbUser->name);
        static::assertSame('inactive', $dbUser->status);
    }

    /**
     * Test: crear posts para usuarios existentes de manera asíncrona.
     */
    public function test_async_create_posts_with_fill_for_existing_users(): void
    {
        // Crear posts para los usuarios del seed (Alice y Bob)
        $post1 = VersaModel::dispense('posts');
        $post1->user_id = 1; // Alice
        $post1->title = 'Async Post with Fill 1';
        $post1->content = 'Content created asynchronously with fill';

        $post2 = VersaModel::dispense('posts');
        $post2->user_id = 2; // Bob
        $post2->title = 'Async Post with Fill 2';
        $post2->content = 'Another async post with fill';

        // Crear promesas
        $promises = [
            async(static function () use ($post1) {
                $post1->store();

                return $post1;
            }),
            async(static function () use ($post2) {
                $post2->store();

                return $post2;
            }),
        ];

        // Esperar resultados
        $savedPosts = await($promises);

        // Verificar
        static::assertCount(2, $savedPosts);

        static::assertNotNull($savedPosts[0]->id);
        static::assertSame('Async Post with Fill 1', $savedPosts[0]->title);
        static::assertSame(1, $savedPosts[0]->user_id);

        static::assertNotNull($savedPosts[1]->id);
        static::assertSame('Async Post with Fill 2', $savedPosts[1]->title);
        static::assertSame(2, $savedPosts[1]->user_id);

        // Verificar en la base de datos
        foreach ($savedPosts as $post) {
            $dbPost = VersaModel::load('posts', $post->id);
            static::assertNotNull($dbPost);
            static::assertSame($post->title, $dbPost->title);
        }
    }

    /**
     * Test: asignación parcial de datos de manera asíncrona.
     */
    public function test_async_partial_fill_passed_by_use(): void
    {
        // Crear usuario con algunos datos
        $user = VersaModel::dispense('users');
        $user->name = 'Initial Name';
        $user->email = 'initial@example.com';

        // Aplicar asignación adicional de manera asíncrona
        $promise = async(static function () use ($user) {
            $user->status = 'pending';
            $user->store();

            return $user;
        });

        // Esperar el resultado
        $savedUser = await($promise);

        // Verificar que se guardaron todos los datos
        static::assertNotNull($savedUser->id);
        static::assertSame('Initial Name', $savedUser->name); // Se mantuvo
        static::assertSame('initial@example.com', $savedUser->email); // Se mantuvo
        static::assertSame('pending', $savedUser->status); // Se agregó

        // Verificar en la base de datos
        $dbUser = VersaModel::load('users', $savedUser->id);
        static::assertSame('Initial Name', $dbUser->name);
        static::assertSame('pending', $dbUser->status);
    }
}
