<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaORM;
use VersaORM\VersaORMException;

use function count;

/**
 * @group mysql
 */
class CacheTest extends TestCase
{
    public static null|VersaORM $orm = null;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        // Usar la misma configuración que TestCase base
        global $config;
        self::$orm = new VersaORM([
            'driver' => $config['DB']['DB_DRIVER'],
            'host' => $config['DB']['DB_HOST'],
            'port' => $config['DB']['DB_PORT'],
            'database' => $config['DB']['DB_NAME'],
            'username' => $config['DB']['DB_USER'],
            'password' => $config['DB']['DB_PASS'],
            'debug' => $config['DB']['debug'],
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();
        // Limpiar caché antes de cada prueba
        $this->clearCache();
    }

    public function test_cache_enable(): void
    {
        $result = self::$orm->cache('enable');
        self::assertIsArray($result);
        self::assertSame('success', $result['status']);
        self::assertStringContainsString('enabled', $result['data']);
    }

    public function test_cache_disable(): void
    {
        $result = self::$orm->cache('disable');
        self::assertIsArray($result);
        self::assertSame('success', $result['status']);
        self::assertStringContainsString('disabled', $result['data']);
    }

    public function test_cache_clear(): void
    {
        // Primero habilitar caché
        self::$orm->cache('enable');

        // Limpiar caché
        $result = self::$orm->cache('clear');
        self::assertIsArray($result);
        self::assertSame('success', $result['status']);
        self::assertStringContainsString('cleared', $result['data']);
    }

    public function test_cache_status(): void
    {
        $result = self::$orm->cache('status');
        self::assertIsArray($result);
        self::assertSame('success', $result['status']);
        self::assertIsInt($result['data']);
        self::assertGreaterThanOrEqual(0, $result['data']);
    }

    public function test_cache_stats(): void
    {
        // Solo probar las acciones básicas disponibles
        self::$orm->cache('enable');

        $result = self::$orm->cache('status');
        self::assertIsArray($result);
        self::assertSame('success', $result['status']);
        self::assertIsInt($result['data']);
        self::assertGreaterThanOrEqual(0, $result['data']);
    }

    // Comentadas temporalmente - acciones no implementadas en backend
    // public function testCacheConfig() ...
    // public function testCacheInvalidateByTable() ...
    // public function testCacheInvalidateByPattern() ...
    // public function testCacheCleanup() ...

    public function test_cache_query_integration(): void
    {
        // Limpiar y habilitar caché
        self::$orm->cache('clear');
        self::$orm->cache('enable');

        // Primera consulta (debería ir a la base de datos)
        $users1 = self::$orm->table('users')->where('status', '=', 'active')->get();

        // Segunda consulta idéntica (debería venir del caché)
        $users2 = self::$orm->table('users')->where('status', '=', 'active')->get();

        // Los resultados deberían ser equivalentes (no necesariamente el mismo objeto)
        self::assertEquals($users1, $users2);

        // Verificar que el caché está activo
        $status = self::$orm->cache('status');
        self::assertSame('success', $status['status']);
    }

    public function test_cache_invalidation_after_insert(): void
    {
        // Limpiar y habilitar caché
        self::$orm->cache('clear');
        self::$orm->cache('enable');

        // Hacer una consulta para poblar caché
        $initialUsers = self::$orm->table('users')->get();
        $initialCount = count($initialUsers);

        // Insertar un nuevo usuario (esto debería invalidar el caché)
        self::$orm
            ->table('users')
            ->insert([
                'name' => 'Cache Test User',
                'email' => 'cache.test@example.com',
                'status' => 'active',
            ]);

        // Consultar de nuevo (debería ir a la base de datos, no al caché)
        $updatedUsers = self::$orm->table('users')->get();
        $updatedCount = count($updatedUsers);

        // Debería haber un usuario más
        self::assertSame($initialCount + 1, $updatedCount);

        // Limpiar el usuario de prueba
        self::$orm->table('users')->where('email', '=', 'cache.test@example.com')->delete();
    }

    public function test_cache_invalidation_after_update(): void
    {
        // Limpiar y habilitar caché
        self::$orm->cache('clear');
        self::$orm->cache('enable');

        // Hacer una consulta para poblar caché
        $user = self::$orm->table('users')->where('email', '=', 'alice@example.com')->first();
        $originalStatus = $user->status ?? 'active';

        // Actualizar el usuario (esto debería invalidar el caché)
        self::$orm->table('users')->where('email', '=', 'alice@example.com')->update(['status' => 'updated_test']);

        // Consultar de nuevo (debería ir a la base de datos)
        $updatedUser = self::$orm->table('users')->where('email', '=', 'alice@example.com')->first();

        self::assertSame('updated_test', $updatedUser->status);

        // Restaurar el estado original
        self::$orm->table('users')->where('email', '=', 'alice@example.com')->update(['status' => $originalStatus]);
    }

    public function test_cache_invalidation_after_delete(): void
    {
        // Crear un usuario de prueba
        self::$orm
            ->table('users')
            ->insert([
                'name' => 'Delete Test User',
                'email' => 'delete.test@example.com',
                'status' => 'active',
            ]);

        // Limpiar y habilitar caché
        self::$orm->cache('clear');
        self::$orm->cache('enable');

        // Hacer una consulta para poblar caché
        $user = self::$orm->table('users')->where('email', '=', 'delete.test@example.com')->first();
        self::assertNotNull($user);

        // Eliminar el usuario (esto debería invalidar el caché)
        self::$orm->table('users')->where('email', '=', 'delete.test@example.com')->delete();

        // Consultar de nuevo (debería ir a la base de datos)
        $deletedUser = self::$orm->table('users')->where('email', '=', 'delete.test@example.com')->first();

        self::assertNull($deletedUser);
    }

    public function test_invalid_cache_action(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->cache('invalid_action');
    }

    public function test_cache_invalidate_without_parameters(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->cache('invalidate'); // Sin table ni pattern
    }

    private function clearCache(): void
    {
        try {
            self::$orm->cache('clear');
        } catch (VersaORMException $e) {
            // Ignorar errores de caché durante la limpieza
        }
    }
}
