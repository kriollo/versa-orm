<?php

// tests/JoinSubDiagnosticTest.php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use Exception;
use PDO;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

use function count;
use function sprintf;

/**
 * Tests específicos para diagnosticar el problema de joinSub
 * Estos tests están diseñados para aislar el problema paso a paso.
 */
/**
 * @group mysql
 */
class JoinSubDiagnosticTest extends TestCase
{
    // ======================================================================
    // Test 1: Verificar que las tablas base funcionan correctamente
    // ======================================================================

    public function test_basic_tables_exist(): void
    {
        // Verificar que las tablas básicas existen y tienen datos
        $users = self::$orm->table('users')->getAll();
        $posts = self::$orm->table('posts')->getAll();

        self::assertGreaterThan(0, count($users));
        self::assertGreaterThan(0, count($posts));

        // Verificar datos base: usuarios y posts encontrados
        self::assertGreaterThan(2, count($users), 'Should have at least 3 users');
        self::assertGreaterThan(2, count($posts), 'Should have at least 3 posts');
    }

    // ======================================================================
    // Test 2: Verificar que los joins básicos funcionan
    // ======================================================================

    public function test_basic_join_works(): void
    {
        $results = self::$orm->table('posts')
            ->select(['posts.title', 'users.name as author'])
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->getAll();

        self::assertGreaterThan(0, count($results));
        self::assertGreaterThanOrEqual(3, count($results), 'Join should return at least 3 results');
    }

    // ======================================================================
    // Test 3: Verificar que las subconsultas simples funcionan
    // ======================================================================

    public function test_basic_subquery_works(): void
    {
        $subquery = self::$orm->table('posts')
            ->select(['user_id', 'COUNT(*) as post_count'])
            ->groupBy('user_id');

        // Verificar que podemos construir la subconsulta
        self::assertInstanceOf(QueryBuilder::class, $subquery);

        // Intentar ejecutar la subconsulta directamente
        try {
            $subResults = $subquery->getAll();
            self::assertGreaterThan(0, count($subResults));
            self::assertGreaterThanOrEqual(2, count($subResults), 'Subquery should return at least 2 results');
        } catch (Exception $e) {
            self::fail('Subquery execution failed: ' . $e->getMessage());
        }
    }

    // ======================================================================
    // Test 4: Verificar que el método joinSub existe
    // ======================================================================

    public function test_join_sub_method_exists(): void
    {
        $query = self::$orm->table('users');
        self::assertTrue(method_exists($query, 'joinSub'));
    }

    // ======================================================================
    // Test 5: Test mínimo de joinSub - solo construcción
    // ======================================================================

    public function test_join_sub_construction(): void
    {
        $subquery = self::$orm->table('posts')
            ->select(['user_id'])
            ->limit(1);

        try {
            $query = self::$orm->table('users')
                ->select(['users.name'])
                ->joinSub($subquery, 'sub', 'users.id', '=', 'sub.user_id');

            self::assertInstanceOf(QueryBuilder::class, $query);
        } catch (Exception $e) {
            throw $e;
        }
    }

    // ======================================================================
    // Test 6: Test mínimo de joinSub - ejecución simple
    // ======================================================================

    public function test_join_sub_minimal_execution(): void
    {
        // Subconsulta lo más simple posible
        $subquery = self::$orm->table('posts')
            ->select(['user_id'])
            ->where('id', '=', 1); // Solo un post específico

        try {
            $results = self::$orm->table('users')
                ->select(['users.name'])
                ->joinSub($subquery, 'sub', 'users.id', '=', 'sub.user_id')
                ->getAll();

            // Agregar debug para ver el SQL generado
            self::assertIsArray($results);
        } catch (Exception $e) {
            throw $e;
        }
    }

    // ======================================================================
    // Test 7: Test de joinSub con COUNT - similar al original que falla
    // ======================================================================

    public function test_join_sub_with_count(): void
    {
        // Esta es la versión que falló originalmente
        $subquery = self::$orm->table('posts')
            ->select(['user_id', 'COUNT(*) as post_count'])
            ->groupBy('user_id')
            ->having('post_count', '>', 1);

        try {
            $results = self::$orm->table('users')
                ->select(['users.name', 'active_users.post_count'])
                ->joinSub($subquery, 'active_users', 'users.id', '=', 'active_users.user_id')
                ->getAll();

            self::assertIsArray($results);

            foreach ($results as $result) {
                self::assertArrayHasKey('name', $result);
                self::assertArrayHasKey('post_count', $result);
                self::assertGreaterThan(1, $result['post_count']);
            }
        } catch (Exception $e) {
            throw $e;
        }
    }

    // ======================================================================
    // Test 8: Verificar SQL generado (debug)
    // ======================================================================

    public function test_join_sub_sql_generation(): void
    {
        // Crear ORM con debug para ver el SQL
        global $config;
        $debugOrm = new VersaORM([
            'driver' => $config['DB']['DB_DRIVER'],
            'host' => $config['DB']['DB_HOST'],
            'port' => $config['DB']['DB_PORT'],
            'database' => $config['DB']['DB_NAME'],
            'username' => $config['DB']['DB_USER'],
            'password' => $config['DB']['DB_PASS'],
            'debug' => true,
        ]);

        $subquery = $debugOrm->table('posts')
            ->select(['user_id', 'COUNT(*) as post_count'])
            ->groupBy('user_id');

        try {
            // Esto debería mostrar el SQL generado

            $query = $debugOrm->table('users')
                ->select(['users.name', 'active_users.post_count'])
                ->joinSub($subquery, 'active_users', 'users.id', '=', 'active_users.user_id');

            // Intentar capturar el SQL sin ejecutar
            self::assertInstanceOf(QueryBuilder::class, $query);
        } catch (Exception $e) {
            throw $e;
        }
    }

    // ======================================================================
    // Test 9: Test directo en MySQL (bypass del ORM)
    // ======================================================================

    public function test_direct_mysql_execution(): void
    {
        // Obtener configuración de la base de datos
        global $config;

        // Crear conexión PDO directa
        $dsn = sprintf(
            '%s:host=%s;port=%s;dbname=%s',
            $config['DB']['DB_DRIVER'],
            $config['DB']['DB_HOST'],
            $config['DB']['DB_PORT'],
            $config['DB']['DB_NAME'],
        );

        try {
            $connection = new PDO(
                $dsn,
                $config['DB']['DB_USER'],
                $config['DB']['DB_PASS'],
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            );

            // SQL manual equivalente a lo que debería generar joinSub
            $sql = 'SELECT users.name, active_users.post_count
                    FROM users
                    INNER JOIN (
                        SELECT user_id, COUNT(*) as post_count
                        FROM posts
                        GROUP BY user_id
                        HAVING post_count > ?
                    ) AS active_users ON users.id = active_users.user_id';

            $stmt = $connection->prepare($sql);
            $stmt->execute([1]);
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

            self::assertIsArray($results);

            // Verificar estructura de datos
            if (! empty($results)) {
                foreach ($results as $result) {
                    self::assertArrayHasKey('name', $result);
                    self::assertArrayHasKey('post_count', $result);
                    self::assertGreaterThan(1, $result['post_count']);
                }
            }
        } catch (Exception $e) {
            throw $e;
        }
    }

    public function test_rust_communication(): void
    {
        // Test simple para verificar que la comunicación con Rust funciona
        try {
            $simpleQuery = self::$orm->table('users')->limit(1);
            $result = $simpleQuery->getAll();

            self::assertIsArray($result);
        } catch (Exception $e) {
            throw $e;
        }
    }
}
