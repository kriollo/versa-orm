<?php

// tests/JoinSubDiagnosticTest.php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use Exception;
use PDO;
use VersaORM\QueryBuilder;

use function count;
use function in_array;
use function sprintf;

/**
 * Tests específicos para diagnosticar el problema de joinSub
 * Estos tests están diseñados para aislar el problema paso a paso.
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
    }

    // ======================================================================
    // Test 3: Verificar que las subconsultas simples funcionan
    // ======================================================================

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
            ->having('COUNT(*)', '>', 1);

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
            // Agregar información adicional del error MySQL
            if ($e->getCode() === 1835) {
                echo "\n[TEST 7] Error MySQL 1835: Malformed communication packet";
                echo "\n[TEST 7] Esto puede indicar problema con la consulta SQL o parámetros";
            }

            throw $e;
        }
    }

    // ======================================================================
    // Test 8: Verificar SQL generado (debug)
    // ======================================================================

    public function test_join_sub_sql_generation(): void
    {
        $subquery = self::$orm->table('posts')
            ->select(['user_id', 'COUNT(*) as post_count'])
            ->groupBy('user_id');

        $query = self::$orm->table('users')
            ->select(['users.name', 'active_users.post_count'])
            ->joinSub($subquery, 'active_users', 'users.id', '=', 'active_users.user_id');

        self::assertInstanceOf(QueryBuilder::class, $query);
    }

    // ======================================================================
    // Test 9: Test directo en MySQL (bypass del ORM)
    // ======================================================================

    /**
     * @group postgresql
     */
    public function test_direct_postgre_sql_execution(): void
    {
        // Verificar si el driver PostgreSQL está disponible
        if (! in_array('pgsql', PDO::getAvailableDrivers(), true)) {
            self::markTestSkipped('PostgreSQL PDO driver not available');
        }

        // Este test ejecuta SQL directo en PostgreSQL para verificar la funcionalidad
        // Obtener configuración de la base de datos
        global $config;

        // Verificar que tenemos configuración PostgreSQL
        if ($config['DB']['DB_DRIVER'] !== 'pgsql') {
            self::markTestSkipped('Test requires PostgreSQL configuration');
        }

        // Crear conexión PDO directa para PostgreSQL
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

            // SQL manual equivalente a lo que debería generar joinSub para PostgreSQL
            $sql = 'SELECT users.name, active_users.post_count
                    FROM users
                    INNER JOIN (
                        SELECT user_id, COUNT(*) as post_count
                        FROM posts
                        GROUP BY user_id
                        HAVING COUNT(*) > $1
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
                    self::assertGreaterThan(1, (int) $result['post_count']);
                }
            }
        } catch (Exception $e) {
            // Si es un error de conexión, marcar como skipped en lugar de fallar
            if (
                strpos($e->getMessage(), 'could not find driver') !== false
                || strpos($e->getMessage(), 'Connection refused') !== false
                || strpos($e->getMessage(), 'could not connect') !== false
            ) {
                self::markTestSkipped('PostgreSQL connection not available: ' . $e->getMessage());
            }

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
