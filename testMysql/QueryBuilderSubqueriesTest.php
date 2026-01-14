<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

/**
 * Tests para subconsultas y expresiones raw en QueryBuilder - Tarea 2.3.
 */
/**
 * @group mysql
 */
class QueryBuilderSubqueriesTest extends TestCase
{
    private ?QueryBuilder $queryBuilder = null;

    private ?VersaORM $orm = null;

    protected function setUp(): void
    {
        // Mock del ORM para testing
        $this->orm = $this->createMock(VersaORM::class);
        $this->queryBuilder = new QueryBuilder($this->orm, 'users');
    }

    /**
     * Test para selectRaw con expresiones seguras.
     */
    public function test_select_raw_with_safe_expressions(): void
    {
        // Expresión segura
        $result = $this->queryBuilder->selectRaw('COUNT(*) as total_users');
        self::assertInstanceOf(QueryBuilder::class, $result);

        // Expresión con bindings
        $result = $this->queryBuilder->selectRaw('UPPER(name) as upper_name', ['test']);
        self::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para selectRaw con expresiones peligrosas.
     */
    public function test_select_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        $this->queryBuilder->selectRaw('name; DROP TABLE users; --');
    }

    /**
     * Test para selectRaw con expresión vacía.
     */
    public function test_select_raw_with_empty_expression(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('selectRaw expression cannot be empty');

        $this->queryBuilder->selectRaw('');
    }

    /**
     * Test para orderByRaw con expresiones seguras.
     */
    public function test_order_by_raw_with_safe_expressions(): void
    {
        $result = $this->queryBuilder->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['active']);
        self::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para orderByRaw con expresiones peligrosas.
     */
    public function test_order_by_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in orderByRaw');

        $this->queryBuilder->orderByRaw('name; DELETE FROM users WHERE 1=1; --');
    }

    /**
     * Test para groupByRaw con expresiones seguras.
     */
    public function test_group_by_raw_with_safe_expressions(): void
    {
        $result = $this->queryBuilder->groupByRaw('YEAR(created_at), MONTH(created_at)');
        self::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para groupByRaw con expresiones peligrosas.
     */
    public function test_group_by_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in groupByRaw');

        $this->queryBuilder->groupByRaw('name UNION SELECT password FROM admin_users');
    }

    /**
     * Test para whereRaw con validación de seguridad.
     */
    public function test_where_raw_with_safe_expressions(): void
    {
        $result = $this->queryBuilder->whereRaw('age > ? AND status = ?', [18, 'active']);
        self::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para whereRaw con expresiones peligrosas.
     */
    public function test_where_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in whereRaw');

        $this->queryBuilder->whereRaw('1=1; DROP TABLE users; --');
    }

    /**
     * Test para selectSubQuery con closure.
     */
    public function test_select_sub_query_with_closure(): void
    {
        $result = $this->queryBuilder->selectSubQuery(static function (QueryBuilder $query): void {
            $query->select(['COUNT(*)'])->where('user_id', '=', 'users.id');
        }, 'posts_count');

        self::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para selectSubQuery con alias inválido.
     */
    public function test_select_sub_query_with_invalid_alias(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid alias name in selectSubQuery');

        $this->queryBuilder->selectSubQuery(static function (QueryBuilder $query): void {
            $query->select(['COUNT(*)']);
        }, 'invalid--alias');
    }

    /**
     * Test para whereSubQuery con operadores válidos.
     */
    public function test_where_sub_query_with_valid_operators(): void
    {
        $result = $this->queryBuilder->whereSubQuery('id', 'IN', static function (QueryBuilder $query): void {
            $query->select(['user_id'])->where('status', '=', 'active');
        });

        self::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para whereSubQuery con operador inválido.
     */
    public function test_where_sub_query_with_invalid_operator(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid operator in whereSubQuery');

        $this->queryBuilder->whereSubQuery('id', 'LIKE', static function (QueryBuilder $query): void {
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

        $this->queryBuilder->whereSubQuery('id; DROP TABLE users', '=', static function (QueryBuilder $query): void {
            $query->select(['user_id']);
        });
    }

    /**
     * Test para whereExists.
     */
    public function test_where_exists(): void
    {
        $result = $this->queryBuilder->whereExists(static function (QueryBuilder $query): void {
            $query->from('posts')->where('user_id', '=', 'users.id');
        });

        self::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para whereNotExists.
     */
    public function test_where_not_exists(): void
    {
        $result = $this->queryBuilder->whereNotExists(static function (QueryBuilder $query): void {
            $query->from('banned_users')->where('user_id', '=', 'users.id');
        });

        self::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para buildSubQuery con QueryBuilder existente.
     */
    public function test_build_sub_query_with_existing_query_builder(): void
    {
        $subQuery = new QueryBuilder($this->orm, 'posts');
        $subQuery->select(['user_id'])->where('status', '=', 'published');

        $result = $this->queryBuilder->whereSubQuery('id', 'IN', $subQuery);
        self::assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para buildSubQuery con tipo inválido.
     */
    public function test_build_sub_query_with_invalid_type(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Subquery callback must be a Closure or QueryBuilder instance');

        // Usar reflexión para acceder al método privado
        $reflection = new ReflectionClass($this->queryBuilder);
        $method = $reflection->getMethod('buildSubQuery');
        $method->setAccessible(true);

        $method->invoke($this->queryBuilder, 'invalid_type');
    }

    /**
     * Test para validación de paréntesis balanceados.
     */
    public function test_unbalanced_parentheses_validation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        $this->queryBuilder->selectRaw('COUNT((posts.id) as total');
    }

    /**
     * Test para expresiones demasiado largas.
     */
    public function test_too_long_expression_validation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        $longExpression = str_repeat('a', 501); // Más de 500 caracteres
        $this->queryBuilder->selectRaw($longExpression);
    }

    /**
     * Test para detección de comentarios SQL.
     */
    public function test_sql_comments_detection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        $this->queryBuilder->selectRaw('name /* comment */ as user_name');
    }

    /**
     * Test para detección de UNION attacks.
     */
    public function test_union_attack_detection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        $this->queryBuilder->selectRaw('name UNION SELECT password FROM admin');
    }

    /**
     * Test para detección de funciones peligrosas.
     */
    public function test_dangerous_function_detection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        $this->queryBuilder->selectRaw('LOAD_FILE("/etc/passwd") as content');
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
            $result = $this->queryBuilder->selectRaw($function . ' as result');
            self::assertInstanceOf(QueryBuilder::class, $result);
        }
    }

    /**
     * Test combinado: subconsulta compleja con múltiples condiciones.
     */
    public function test_complex_subquery_with_multiple_conditions(): void
    {
        $result = $this->queryBuilder
            ->select(['id', 'name', 'email'])
            ->selectSubQuery(static function (QueryBuilder $query): void {
                $query->select(['COUNT(*)'])->where('user_id', '=', 'users.id')->where('status', '=', 'published');
            }, 'published_posts_count')
            ->whereExists(static function (QueryBuilder $query): void {
                $query->from('user_roles')->where('user_id', '=', 'users.id')->where('role', '=', 'author');
            })
            ->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['premium'])
            ->groupByRaw('YEAR(created_at), status');

        self::assertInstanceOf(QueryBuilder::class, $result);
    }
}
