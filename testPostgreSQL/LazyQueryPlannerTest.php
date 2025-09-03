<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use Exception;
use ReflectionClass;
use VersaORM\QueryBuilder;

use function count;

/**
 * Tests para modo lazy y planificador de consultas.
 */
class LazyQueryPlannerTest extends TestCase
{
    protected function tearDown(): void
    {
        // El TestCase base ya maneja la limpieza
        parent::tearDown();
    }

    public function test_lazy_mode_activation(): void
    {
        $query = self::$orm->table('users')->lazy();

        $reflection = new ReflectionClass($query);
        $isLazyProperty = $reflection->getProperty('isLazy');
        $isLazyProperty->setAccessible(true);

        self::assertTrue($isLazyProperty->getValue($query));
    }

    public function test_lazy_query_building(): void
    {
        $query = self::$orm
            ->table('users')
            ->lazy()
            ->select(['id', 'name'])
            ->where('active', '=', true)
            ->orderBy('name', 'ASC')
            ->limit(10);

        // La consulta no se ejecuta hasta collect()
        self::assertInstanceOf(QueryBuilder::class, $query);
    }

    public function test_collect_executes_lazy_query(): void
    {
        // Crear datos de prueba
        self::$orm->exec("INSERT INTO users (name, email, status) VALUES ('Test User', 'test@example.com', 'active')");

        $results = self::$orm
            ->table('users')
            ->lazy()
            ->select(['name', 'email'])
            ->where('status', '=', 'active')
            ->collect();

        self::assertIsArray($results);
        self::assertNotEmpty($results);
        self::assertArrayHasKey('name', $results[0]);
    }

    public function test_chain_multiple_queries(): void
    {
        $query1 = self::$orm->table('users')->select(['id', 'name'])->lazy();
        $query2 = self::$orm->table('users')->select(['email', 'active'])->lazy();

        $chainedQuery = $query1->chain($query2);

        self::assertInstanceOf(QueryBuilder::class, $chainedQuery);
    }

    public function test_explain_plan(): void
    {
        $explanation = self::$orm
            ->table('users')
            ->lazy()
            ->select(['id', 'name'])
            ->where('status', '=', 'active')
            ->join('posts', 'users.id', '=', 'posts.user_id')
            ->explain();

        self::assertIsArray($explanation);
        self::assertArrayHasKey('plan', $explanation);
        self::assertArrayHasKey('generated_sql', $explanation);
        self::assertArrayHasKey('estimated_cost', $explanation['plan']);
    }

    public function test_complex_lazy_query(): void
    {
        // Insertar datos de prueba
        self::$orm->exec("INSERT INTO users (name, email, status) VALUES
            ('User 1', 'user1@example.com', 'active'),
            ('User 2', 'user2@example.com', 'active'),
            ('User 3', 'user3@example.com', 'inactive')");

        $results = self::$orm
            ->table('users')
            ->lazy()
            ->select(['users.id', 'users.name', 'users.email'])
            ->where('users.status', '=', 'active')
            ->where('users.name', 'LIKE', 'User%')
            ->orderBy('users.name', 'ASC')
            ->limit(5)
            ->collect();

        self::assertIsArray($results);
        self::assertCount(2, $results); // Solo usuarios activos
        self::assertSame('User 1', $results[0]['name']);
        self::assertSame('User 2', $results[1]['name']);
    }

    public function test_lazy_query_with_joins(): void
    {
        // Insertar datos de prueba (la tabla posts ya existe del TestCase base)
        self::$orm->exec("INSERT INTO users (name, email, status) VALUES
            ('Join User 1', 'join1@example.com', 'active'),
            ('Join User 2', 'join2@example.com', 'active')");

        self::$orm->exec("INSERT INTO posts (user_id, title, content) VALUES
            (1, 'Post 1', 'Content 1'),
            (1, 'Post 2', 'Content 2'),
            (2, 'Post 3', 'Content 3')");

        $results = self::$orm
            ->table('users')
            ->lazy()
            ->select(['users.name', 'posts.title'])
            ->join('posts', 'users.id', '=', 'posts.user_id')
            ->where('users.status', '=', 'active')
            ->collect();

        self::assertIsArray($results);
        self::assertNotEmpty($results);
        self::assertArrayHasKey('name', $results[0]);
        self::assertArrayHasKey('title', $results[0]);
    }

    public function test_query_optimization(): void
    {
        $explanation = self::$orm
            ->table('users')
            ->lazy()
            ->select(['id'])
            ->where('status', '=', 'active')
            ->where('verified', '=', true)
            ->explain();

        self::assertIsArray($explanation);
        self::assertArrayHasKey('plan', $explanation);

        // Verificar que se aplicaron optimizaciones
        if (isset($explanation['optimizations_applied'])) {
            self::assertIsBool($explanation['optimizations_applied']);
        }
    }

    public function test_performance_comparison(): void
    {
        // Crear más datos de prueba para comparación
        for ($i = 1; $i <= 100; $i++) {
            self::$orm->exec("INSERT INTO users (name, email, status) VALUES
                ('User {$i}', 'user{$i}@example.com', '"
            . (($i % 2) === 0 ? 'active' : 'inactive')
            . "')");
        }

        // Consulta normal
        $start = microtime(true);
        $normalResults = self::$orm->table('users')->select(['id', 'name'])->where('status', '=', 'active')->get();
        $normalTime = microtime(true) - $start;

        // Consulta lazy
        $start = microtime(true);
        $lazyResults = self::$orm
            ->table('users')
            ->lazy()
            ->select(['id', 'name'])
            ->where('status', '=', 'active')
            ->collect();
        $lazyTime = microtime(true) - $start;

        // Verificar que los resultados son equivalentes
        self::assertCount(count($normalResults), $lazyResults);

        // Para consultas simples, la diferencia de tiempo no debería ser muy grande
        $timeDifference = abs($normalTime - $lazyTime);
        self::assertLessThan(1.0, $timeDifference, 'Time difference should be minimal for simple queries');
    }

    public function test_lazy_query_with_complex_operations(): void
    {
        $results = self::$orm
            ->table('users')
            ->lazy()
            ->select(['users.name', 'COUNT(posts.id) as post_count'])
            ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
            ->where('users.status', '=', 'active')
            ->groupBy(['users.id', 'users.name'])
            ->having('COUNT(posts.id)', '>=', 0)
            ->orderBy('post_count', 'DESC')
            ->limit(10)
            ->collect();

        self::assertIsArray($results);
    }

    public function test_error_handling_in_lazy_mode(): void
    {
        $this->expectException(Exception::class);

        // Intentar usar una tabla que no existe
        self::$orm->table('nonexistent_table')->lazy()->select(['id'])->collect();
    }

    public function test_lazy_query_sql_generation(): void
    {
        $explanation = self::$orm
            ->table('users')
            ->lazy()
            ->select(['id', 'name', 'email'])
            ->where('status', '=', 'active')
            ->where('verified', '=', true)
            ->orderBy('name', 'ASC')
            ->explain();

        $sql = $explanation['generated_sql'];

        self::assertIsString($sql);
        self::assertStringContainsString('SELECT', $sql);
        // Aceptar FROM users o FROM "users" segun dialecto
        self::assertMatchesRegularExpression('/FROM\s+"?users"?/i', $sql);
        self::assertStringContainsString('WHERE', $sql);
        self::assertStringContainsString('ORDER BY', $sql);
    }
}
