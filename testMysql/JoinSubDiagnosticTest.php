<?php

// tests/JoinSubDiagnosticTest.php

declare(strict_types=1);

namespace VersaORM\Tests;

/**
 * Tests específicos para diagnosticar el problema de joinSub
 * Estos tests están diseñados para aislar el problema paso a paso.
 */
class JoinSubDiagnosticTest extends TestCase
{
    //======================================================================
    // Test 1: Verificar que las tablas base funcionan correctamente
    //======================================================================

    public function testBasicTablesExist(): void
    {
        // Verificar que las tablas básicas existen y tienen datos
        $users = self::$orm->table('users')->getAll();
        $posts = self::$orm->table('posts')->getAll();

        $this->assertGreaterThan(0, count($users));
        $this->assertGreaterThan(0, count($posts));

        echo "\n[TEST 1] Usuarios encontrados: " . count($users);
        echo "\n[TEST 1] Posts encontrados: " . count($posts);
    }

    //======================================================================
    // Test 2: Verificar que los joins básicos funcionan
    //======================================================================

    public function testBasicJoinWorks(): void
    {
        $results = self::$orm->table('posts')
            ->select(['posts.title', 'users.name as author'])
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->getAll();

        $this->assertGreaterThan(0, count($results));
        echo "\n[TEST 2] Join básico funcionó. Resultados: " . count($results);
    }

    //======================================================================
    // Test 3: Verificar que las subconsultas simples funcionan
    //======================================================================

    public function testBasicSubqueryWorks(): void
    {
        $subquery = self::$orm->table('posts')
            ->select(['user_id', 'COUNT(*) as post_count'])
            ->groupBy('user_id');

        // Verificar que podemos construir la subconsulta
        $this->assertInstanceOf(\VersaORM\QueryBuilder::class, $subquery);
        echo "\n[TEST 3] Subconsulta construida correctamente";

        // Intentar ejecutar la subconsulta directamente
        try {
            $subResults = $subquery->getAll();
            $this->assertGreaterThan(0, count($subResults));
            echo "\n[TEST 3] Subconsulta ejecutada directamente. Resultados: " . count($subResults);
        } catch (\Exception $e) {
            echo "\n[TEST 3] ERROR ejecutando subconsulta: " . $e->getMessage();
            throw $e;
        }
    }

    //======================================================================
    // Test 4: Verificar que el método joinSub existe
    //======================================================================

    public function testJoinSubMethodExists(): void
    {
        $query = self::$orm->table('users');
        $this->assertTrue(method_exists($query, 'joinSub'));
        echo "\n[TEST 4] Método joinSub existe";
    }

    //======================================================================
    // Test 5: Test mínimo de joinSub - solo construcción
    //======================================================================

    public function testJoinSubConstruction(): void
    {
        $subquery = self::$orm->table('posts')
            ->select(['user_id'])
            ->limit(1);

        try {
            $query = self::$orm->table('users')
                ->select(['users.name'])
                ->joinSub($subquery, 'sub', 'users.id', '=', 'sub.user_id');

            $this->assertInstanceOf(\VersaORM\QueryBuilder::class, $query);
            echo "\n[TEST 5] joinSub construido correctamente";
        } catch (\Exception $e) {
            echo "\n[TEST 5] ERROR construyendo joinSub: " . $e->getMessage();
            throw $e;
        }
    }

    //======================================================================
    // Test 6: Test mínimo de joinSub - ejecución simple
    //======================================================================

    public function testJoinSubMinimalExecution(): void
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

            echo "\n[TEST 6] joinSub mínimo ejecutado. SQL y parámetros:";
            // Agregar debug para ver el SQL generado
            $this->assertIsArray($results);
            echo "\n[TEST 6] Resultados: " . count($results);
        } catch (\Exception $e) {
            echo "\n[TEST 6] ERROR ejecutando joinSub mínimo: " . $e->getMessage();
            echo "\n[TEST 6] Tipo de error: " . get_class($e);
            echo "\n[TEST 6] Código: " . $e->getCode();
            throw $e;
        }
    }

    //======================================================================
    // Test 7: Test de joinSub con COUNT - similar al original que falla
    //======================================================================

    public function testJoinSubWithCount(): void
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

            echo "\n[TEST 7] joinSub con COUNT ejecutado correctamente";
            $this->assertIsArray($results);

            foreach ($results as $result) {
                $this->assertArrayHasKey('name', $result);
                $this->assertArrayHasKey('post_count', $result);
                $this->assertGreaterThan(1, $result['post_count']);
            }

            echo "\n[TEST 7] Resultados validados: " . count($results);
        } catch (\Exception $e) {
            echo "\n[TEST 7] ERROR ejecutando joinSub con COUNT: " . $e->getMessage();
            echo "\n[TEST 7] Tipo de error: " . get_class($e);
            echo "\n[TEST 7] Código: " . $e->getCode();

            // Agregar información adicional del error MySQL
            if ($e->getCode() === 1835) {
                echo "\n[TEST 7] Error MySQL 1835: Malformed communication packet";
                echo "\n[TEST 7] Esto puede indicar problema con la consulta SQL o parámetros";
            }

            throw $e;
        }
    }

    //======================================================================
    // Test 8: Verificar SQL generado (debug)
    //======================================================================

    public function testJoinSubSqlGeneration(): void
    {
        // Crear ORM con debug para ver el SQL
        global $config;
        $debugOrm = new \VersaORM\VersaORM([
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
            echo "\n[TEST 8] Generando SQL con debug activado...";

            $query = $debugOrm->table('users')
                ->select(['users.name', 'active_users.post_count'])
                ->joinSub($subquery, 'active_users', 'users.id', '=', 'active_users.user_id');

            // Intentar capturar el SQL sin ejecutar
            $this->assertInstanceOf(\VersaORM\QueryBuilder::class, $query);
            echo "\n[TEST 8] Query construido para debug";
        } catch (\Exception $e) {
            echo "\n[TEST 8] ERROR en generación SQL: " . $e->getMessage();
            throw $e;
        }
    }

    //======================================================================
    // Test 9: Test directo en MySQL (bypass del ORM)
    //======================================================================

    public function testDirectMysqlExecution(): void
    {
        // Obtener configuración de la base de datos
        global $config;

        // Crear conexión PDO directa
        $dsn = sprintf(
            '%s:host=%s;port=%s;dbname=%s',
            $config['DB']['DB_DRIVER'],
            $config['DB']['DB_HOST'],
            $config['DB']['DB_PORT'],
            $config['DB']['DB_NAME']
        );

        try {
            $connection = new \PDO(
                $dsn,
                $config['DB']['DB_USER'],
                $config['DB']['DB_PASS'],
                [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]
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
            $results = $stmt->fetchAll(\PDO::FETCH_ASSOC);

            echo '
[TEST 9] SQL directo ejecutado correctamente';
            echo '
[TEST 9] Resultados: ' . count($results);

            $this->assertIsArray($results);

            // Verificar estructura de datos
            if (!empty($results)) {
                foreach ($results as $result) {
                    $this->assertArrayHasKey('name', $result);
                    $this->assertArrayHasKey('post_count', $result);
                    $this->assertGreaterThan(1, $result['post_count']);
                }
            }

        } catch (\Exception $e) {
            echo '
[TEST 9] ERROR ejecutando SQL directo: ' . $e->getMessage();
            echo '
[TEST 9] Código de error: ' . $e->getCode();
            throw $e;
        }
    }

    public function testRustCommunication(): void
    {
        // Test simple para verificar que la comunicación con Rust funciona
        try {
            $simpleQuery = self::$orm->table('users')->limit(1);
            $result = $simpleQuery->getAll();

            echo "\n[TEST 10] Comunicación básica PHP-Rust funciona";
            $this->assertIsArray($result);
        } catch (\Exception $e) {
            echo "\n[TEST 10] ERROR en comunicación PHP-Rust: " . $e->getMessage();
            throw $e;
        }
    }
}
