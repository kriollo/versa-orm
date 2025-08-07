<?php

declare(strict_types=1);

namespace VersaORM\Tests;

use VersaORM\QueryBuilder;

/**
 * Tests para modo lazy y planificador de consultas
 */
class LazyQueryPlannerTest extends TestCase
{
    public function testLazyModeActivation(): void
    {
        $query = self::$orm->table('users')->lazy();

        $reflection = new \ReflectionClass($query);
        $isLazyProperty = $reflection->getProperty('isLazy');
        $isLazyProperty->setAccessible(true);

        $this->assertTrue($isLazyProperty->getValue($query));
    }

    public function testLazyQueryBuilding(): void
    {
        $query = self::$orm->table('users')
            ->lazy()
            ->select(['id', 'name'])
            ->where('active', '=', true)
            ->orderBy('name', 'ASC')
            ->limit(10);

        // La consulta no se ejecuta hasta collect()
        $this->assertInstanceOf(QueryBuilder::class, $query);
    }

    public function testCollectExecutesLazyQuery(): void
    {
        // Crear datos de prueba
        self::$orm->exec("INSERT INTO users (name, email, status) VALUES ('Test User', 'test@example.com', 'active')");

        $results = self::$orm->table('users')
            ->lazy()
            ->select(['name', 'email'])
            ->where('status', '=', 'active')
            ->collect();

        $this->assertIsArray($results);
        $this->assertNotEmpty($results);
        $this->assertArrayHasKey('name', $results[0]);
    }

    public function testChainMultipleQueries(): void
    {
        $query1 = self::$orm->table('users')->select(['id', 'name'])->lazy();
        $query2 = self::$orm->table('users')->select(['email', 'active'])->lazy();

        $chainedQuery = $query1->chain($query2);

        $this->assertInstanceOf(QueryBuilder::class, $chainedQuery);
    }

    public function testExplainPlan(): void
    {
        $explanation = self::$orm->table('users')
            ->lazy()
            ->select(['id', 'name'])
            ->where('status', '=', 'active')
            ->join('posts', 'users.id', '=', 'posts.user_id')
            ->explain();

        $this->assertIsArray($explanation);
        $this->assertArrayHasKey('plan', $explanation);
        $this->assertArrayHasKey('generated_sql', $explanation);
        $this->assertArrayHasKey('estimated_cost', $explanation['plan']);
    }

    public function testComplexLazyQuery(): void
    {
        // Insertar datos de prueba
        self::$orm->exec("INSERT INTO users (name, email, status) VALUES
            ('User 1', 'user1@example.com', 'active'),
            ('User 2', 'user2@example.com', 'active'),
            ('User 3', 'user3@example.com', 'inactive')");

        $results = self::$orm->table('users')
            ->lazy()
            ->select(['users.id', 'users.name', 'users.email'])
            ->where('users.status', '=', 'active')
            ->where('users.name', 'LIKE', 'User%')
            ->orderBy('users.name', 'ASC')
            ->limit(5)
            ->collect();

        $this->assertIsArray($results);
        $this->assertCount(2, $results); // Solo usuarios activos
        $this->assertEquals('User 1', $results[0]['name']);
        $this->assertEquals('User 2', $results[1]['name']);
    }

    public function testLazyQueryWithJoins(): void
    {
        // Insertar datos de prueba (la tabla posts ya existe del TestCase base)
        self::$orm->exec("INSERT INTO users (name, email, status) VALUES
            ('Join User 1', 'join1@example.com', 'active'),
            ('Join User 2', 'join2@example.com', 'active')");

        self::$orm->exec("INSERT INTO posts (user_id, title, content) VALUES
            (1, 'Post 1', 'Content 1'),
            (1, 'Post 2', 'Content 2'),
            (2, 'Post 3', 'Content 3')");

        $results = self::$orm->table('users')
            ->lazy()
            ->select(['users.name', 'posts.title'])
            ->join('posts', 'users.id', '=', 'posts.user_id')
            ->where('users.status', '=', 'active')
            ->collect();

        $this->assertIsArray($results);
        $this->assertNotEmpty($results);
        $this->assertArrayHasKey('name', $results[0]);
        $this->assertArrayHasKey('title', $results[0]);
    }
    public function testQueryOptimization(): void
    {
        $explanation = self::$orm->table('users')
            ->lazy()
            ->select(['id'])
            ->where('status', '=', 'active')
            ->where('verified', '=', true)
            ->explain();

        $this->assertIsArray($explanation);
        $this->assertArrayHasKey('plan', $explanation);

        // Verificar que se aplicaron optimizaciones
        if (isset($explanation['optimizations_applied'])) {
            $this->assertIsBool($explanation['optimizations_applied']);
        }
    }

    public function testPerformanceComparison(): void
    {
        // Crear más datos de prueba para comparación
        for ($i = 1; $i <= 100; $i++) {
            self::$orm->exec("INSERT INTO users (name, email, status) VALUES
                ('User $i', 'user$i@example.com', '" . (($i % 2 == 0) ? 'active' : 'inactive') . "')");
        }

        // Consulta normal
        $start = microtime(true);
        $normalResults = self::$orm->table('users')
            ->select(['id', 'name'])
            ->where('status', '=', 'active')
            ->get();
        $normalTime = microtime(true) - $start;

        // Consulta lazy
        $start = microtime(true);
        $lazyResults = self::$orm->table('users')
            ->lazy()
            ->select(['id', 'name'])
            ->where('status', '=', 'active')
            ->collect();
        $lazyTime = microtime(true) - $start;

        // Verificar que los resultados son equivalentes
        $this->assertCount(count($normalResults), $lazyResults);

        // Para consultas simples, la diferencia de tiempo no debería ser muy grande
        $timeDifference = abs($normalTime - $lazyTime);
        $this->assertLessThan(1.0, $timeDifference, 'Time difference should be minimal for simple queries');
    }

    public function testLazyQueryWithComplexOperations(): void
    {
        $results = self::$orm->table('users')
            ->lazy()
            ->select(['users.name', 'COUNT(posts.id) as post_count'])
            ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
            ->where('users.status', '=', 'active')
            ->groupBy(['users.id', 'users.name'])
            ->having('COUNT(posts.id)', '>=', 0)
            ->orderBy('post_count', 'DESC')
            ->limit(10)
            ->collect();

        $this->assertIsArray($results);
    }

    public function testErrorHandlingInLazyMode(): void
    {
        $this->expectException(\Exception::class);

        // Intentar usar una tabla que no existe
        self::$orm->table('nonexistent_table')
            ->lazy()
            ->select(['id'])
            ->collect();
    }

    public function testLazyQuerySQLGeneration(): void
    {
        $explanation = self::$orm->table('users')
            ->lazy()
            ->select(['id', 'name', 'email'])
            ->where('status', '=', 'active')
            ->where('verified', '=', true)
            ->orderBy('name', 'ASC')
            ->explain();

        $sql = $explanation['generated_sql'];

        $this->assertIsString($sql);
        $this->assertStringContainsString('SELECT', $sql);
        $this->assertStringContainsString('FROM users', $sql);
        $this->assertStringContainsString('WHERE', $sql);
        $this->assertStringContainsString('ORDER BY', $sql);
    }

    protected function tearDown(): void
    {
        // El TestCase base ya maneja la limpieza
        parent::tearDown();
    }
}
