<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use ReflectionClass;
use VersaORM\QueryBuilder;
use VersaORM\VersaORMException;

/**
 * Tests para subconsultas y expresiones raw en QueryBuilder - Tarea 2.3.
 */
class QueryBuilderSubqueriesTest extends TestCase
{
    protected function setUp(): void
    {
        // Mock del ORM para testing
        parent::setUp();
    }

    /**
     * Test para selectRaw con expresiones seguras.
     */
    public function test_select_raw_with_safe_expressions(): void
    {
        // Expresión segura
        $result = self::$orm->table('users')->selectRaw('COUNT(*) as total_users');
        static::assertInstanceOf(QueryBuilder::class, $result);

        // Expresión con bindings
        $result = self::$orm->table('users')->selectRaw('UPPER(name) as upper_name', ['test']);
        static::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para selectRaw con expresiones peligrosas.
     */
    public function test_select_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('name; DROP TABLE users; --');
    }

    /**
     * Test para selectRaw con expresión vacía.
     */
    public function test_select_raw_with_empty_expression(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('selectRaw expression cannot be empty');

        self::$orm->table('users')->selectRaw('');
    }

    /**
     * Test para orderByRaw con expresiones seguras.
     */
    public function test_order_by_raw_with_safe_expressions(): void
    {
        $result = self::$orm->table('users')->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['active']);
        static::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para orderByRaw con expresiones peligrosas.
     */
    public function test_order_by_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in orderByRaw');

        self::$orm->table('users')->orderByRaw('name; DELETE FROM users WHERE 1=1; --');
    }

    /**
     * Test para groupByRaw con expresiones seguras.
     */
    public function test_group_by_raw_with_safe_expressions(): void
    {
        $result = self::$orm->table('users')->groupByRaw('YEAR(created_at), MONTH(created_at)');
        static::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para groupByRaw con expresiones peligrosas.
     */
    public function test_group_by_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in groupByRaw');

        self::$orm->table('users')->groupByRaw('name UNION SELECT password FROM admin_users');
    }

    /**
     * Test para whereRaw con validación de seguridad.
     */
    public function test_where_raw_with_safe_expressions(): void
    {
        $result = self::$orm->table('users')->whereRaw('age > ? AND status = ?', [18, 'active']);
        static::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para whereRaw con expresiones peligrosas.
     */
    public function test_where_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in whereRaw');

        self::$orm->table('users')->whereRaw('1=1; DROP TABLE users; --');
    }

    /**
     * Test para selectSubQuery con closure.
     */
    public function test_select_sub_query_with_closure(): void
    {
        $result = self::$orm
            ->table('users')
            ->selectSubQuery(static function (QueryBuilder $query): void {
                $query->select(['COUNT(*)'])->where('user_id', '=', 'users.id');
            }, 'posts_count');

        static::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para selectSubQuery con alias inválido.
     */
    public function test_select_sub_query_with_invalid_alias(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid alias name in selectSubQuery');

        self::$orm
            ->table('users')
            ->selectSubQuery(static function (QueryBuilder $query): void {
                $query->select(['COUNT(*)']);
            }, 'invalid--alias');
    }

    /**
     * Test para whereSubQuery con operadores válidos.
     */
    public function test_where_sub_query_with_valid_operators(): void
    {
        $result = self::$orm
            ->table('users')
            ->whereSubQuery('id', 'IN', static function (QueryBuilder $query): void {
                $query->select(['user_id'])->where('status', '=', 'active');
            });

        static::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para whereSubQuery con operador inválido.
     */
    public function test_where_sub_query_with_invalid_operator(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid operator in whereSubQuery');

        self::$orm
            ->table('users')
            ->whereSubQuery('id', 'LIKE', static function (QueryBuilder $query): void {
                $query->select(['user_id']);
            });
    }

    /**
     * Test para whereSubQuery con columna inválida.
     */
    public function test_where_sub_query_with_invalid_column(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid column name in whereSubQuery');

        self::$orm
            ->table('users')
            ->whereSubQuery('id; DROP TABLE users', '=', static function (QueryBuilder $query): void {
                $query->select(['user_id']);
            });
    }

    /**
     * Test para whereExists.
     */
    public function test_where_exists(): void
    {
        $result = self::$orm
            ->table('users')
            ->whereExists(static function (QueryBuilder $query): void {
                $query->from('posts')->where('user_id', '=', 'users.id');
            });

        static::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para whereNotExists.
     */
    public function test_where_not_exists(): void
    {
        $result = self::$orm
            ->table('users')
            ->whereNotExists(static function (QueryBuilder $query): void {
                $query->from('banned_users')->where('user_id', '=', 'users.id');
            });

        static::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para buildSubQuery con QueryBuilder existente.
     */
    public function test_build_sub_query_with_existing_query_builder(): void
    {
        // Construir el QueryBuilder existente a partir del ORM estático para evitar notices
        $subQuery = self::$orm->table('posts');
        $subQuery->select(['user_id'])->where('status', '=', 'published');

        $result = self::$orm->table('users')->whereSubQuery('id', 'IN', $subQuery);
        static::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para buildSubQuery con tipo inválido.
     */
    public function test_build_sub_query_with_invalid_type(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Subquery callback must be a Closure or QueryBuilder instance');

        // Usar reflexión para acceder al método privado
        $reflection = new ReflectionClass(self::$orm->table('users'));
        $method = $reflection->getMethod('buildSubQuery');
        $method->setAccessible(true);

        $method->invoke(self::$orm->table('users'), 'invalid_type');
    }

    /**
     * Test para validación de paréntesis balanceados.
     */
    public function test_unbalanced_parentheses_validation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('COUNT((posts.id) as total');
    }

    /**
     * Test para expresiones demasiado largas.
     */
    public function test_too_long_expression_validation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        $longExpression = str_repeat('a', 501); // Más de 500 caracteres
        self::$orm->table('users')->selectRaw($longExpression);
    }

    /**
     * Test para detección de comentarios SQL.
     */
    public function test_sql_comments_detection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('name /* comment */ as user_name');
    }

    /**
     * Test para detección de UNION attacks.
     */
    public function test_union_attack_detection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('name UNION SELECT password FROM admin');
    }

    /**
     * Test para detección de funciones peligrosas.
     */
    public function test_dangerous_function_detection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('LOAD_FILE("/etc/passwd") as content');
    }

    /**
     * Test para funciones SQL permitidas.
     */
    public function test_allowed_sql_functions(): void
    {
        $allowedFunctions = [
            'COUNT(*)',
            'SUM(amount)',
            'AVG(score)',
            'MAX(created_at)',
            'MIN(price)',
            'UPPER(name)',
            'LOWER(email)',
            'LENGTH(description)',
            'CONCAT(first_name, last_name)',
            'COALESCE(phone, email)',
            'YEAR(created_at)',
            'MONTH(date_field)',
            'DAY(timestamp_field)',
        ];

        foreach ($allowedFunctions as $function) {
            $result = self::$orm->table('users')->selectRaw($function . ' as result');
            static::assertInstanceOf(QueryBuilder::class, $result);
        }
    }

    /**
     * Test combinado: subconsulta compleja con múltiples condiciones.
     */
    public function test_complex_subquery_with_multiple_conditions(): void
    {
        $result = self::$orm
            ->table('users')
            ->select(['id', 'name', 'email'])
            ->selectSubQuery(static function (QueryBuilder $query): void {
                $query->select(['COUNT(*)'])->where('user_id', '=', 'users.id')->where('status', '=', 'published');
            }, 'published_posts_count')
            ->whereExists(static function (QueryBuilder $query): void {
                $query->from('user_roles')->where('user_id', '=', 'users.id')->where('role', '=', 'author');
            })
            ->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['premium'])
            ->groupByRaw('YEAR(created_at), status');

        static::assertInstanceOf(QueryBuilder::class, $result);
    }
}
