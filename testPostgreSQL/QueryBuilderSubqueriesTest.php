<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaORMException;
use VersaORM\QueryBuilder;

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
    public function testSelectRawWithSafeExpressions(): void
    {
        // Expresión segura
        $result = self::$orm->table('users')->selectRaw('COUNT(*) as total_users');
        $this->assertInstanceOf(QueryBuilder::class, $result);

        // Expresión con bindings
        $result = self::$orm->table('users')->selectRaw('UPPER(name) as upper_name', ['test']);
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para selectRaw con expresiones peligrosas.
     */
    public function testSelectRawWithUnsafeExpressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('name; DROP TABLE users; --');
    }

    /**
     * Test para selectRaw con expresión vacía.
     */
    public function testSelectRawWithEmptyExpression(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('selectRaw expression cannot be empty');

        self::$orm->table('users')->selectRaw('');
    }

    /**
     * Test para orderByRaw con expresiones seguras.
     */
    public function testOrderByRawWithSafeExpressions(): void
    {
        $result = self::$orm->table('users')->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['active']);
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para orderByRaw con expresiones peligrosas.
     */
    public function testOrderByRawWithUnsafeExpressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in orderByRaw');

        self::$orm->table('users')->orderByRaw('name; DELETE FROM users WHERE 1=1; --');
    }

    /**
     * Test para groupByRaw con expresiones seguras.
     */
    public function testGroupByRawWithSafeExpressions(): void
    {
        $result = self::$orm->table('users')->groupByRaw('YEAR(created_at), MONTH(created_at)');
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para groupByRaw con expresiones peligrosas.
     */
    public function testGroupByRawWithUnsafeExpressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in groupByRaw');

        self::$orm->table('users')->groupByRaw('name UNION SELECT password FROM admin_users');
    }

    /**
     * Test para whereRaw con validación de seguridad.
     */
    public function testWhereRawWithSafeExpressions(): void
    {
        $result = self::$orm->table('users')->whereRaw('age > ? AND status = ?', [18, 'active']);
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para whereRaw con expresiones peligrosas.
     */
    public function testWhereRawWithUnsafeExpressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in whereRaw');

        self::$orm->table('users')->whereRaw('1=1; DROP TABLE users; --');
    }

    /**
     * Test para selectSubQuery con closure.
     */
    public function testSelectSubQueryWithClosure(): void
    {
        $result = self::$orm->table('users')->selectSubQuery(function (QueryBuilder $query): void {
            $query->select(['COUNT(*)'])->where('user_id', '=', 'users.id');
        }, 'posts_count');

        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para selectSubQuery con alias inválido.
     */
    public function testSelectSubQueryWithInvalidAlias(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid alias name in selectSubQuery');

        self::$orm->table('users')->selectSubQuery(function (QueryBuilder $query): void {
            $query->select(['COUNT(*)']);
        }, 'invalid--alias');
    }

    /**
     * Test para whereSubQuery con operadores válidos.
     */
    public function testWhereSubQueryWithValidOperators(): void
    {
        $result = self::$orm->table('users')->whereSubQuery('id', 'IN', function (QueryBuilder $query): void {
            $query->select(['user_id'])->where('status', '=', 'active');
        });

        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para whereSubQuery con operador inválido.
     */
    public function testWhereSubQueryWithInvalidOperator(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid operator in whereSubQuery');

        self::$orm->table('users')->whereSubQuery('id', 'LIKE', function (QueryBuilder $query): void {
            $query->select(['user_id']);
        });
    }

    /**
     * Test para whereSubQuery con columna inválida.
     */
    public function testWhereSubQueryWithInvalidColumn(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid column name in whereSubQuery');

        self::$orm->table('users')->whereSubQuery('id; DROP TABLE users', '=', function (QueryBuilder $query): void {
            $query->select(['user_id']);
        });
    }

    /**
     * Test para whereExists.
     */
    public function testWhereExists(): void
    {
        $result = self::$orm->table('users')->whereExists(function (QueryBuilder $query): void {
            $query->from('posts')->where('user_id', '=', 'users.id');
        });

        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para whereNotExists.
     */
    public function testWhereNotExists(): void
    {
        $result = self::$orm->table('users')->whereNotExists(function (QueryBuilder $query): void {
            $query->from('banned_users')->where('user_id', '=', 'users.id');
        });

        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para buildSubQuery con QueryBuilder existente.
     */
    public function testBuildSubQueryWithExistingQueryBuilder(): void
    {
        $subQuery = new QueryBuilder($this->orm, 'posts');
        $subQuery->select(['user_id'])->where('status', '=', 'published');

        $result = self::$orm->table('users')->whereSubQuery('id', 'IN', $subQuery);
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    /**
     * Test para buildSubQuery con tipo inválido.
     */
    public function testBuildSubQueryWithInvalidType(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Subquery callback must be a Closure or QueryBuilder instance');

        // Usar reflexión para acceder al método privado
        $reflection = new \ReflectionClass(self::$orm->table('users'));
        $method = $reflection->getMethod('buildSubQuery');
        $method->setAccessible(true);

        $method->invoke(self::$orm->table('users'), 'invalid_type');
    }

    /**
     * Test para validación de paréntesis balanceados.
     */
    public function testUnbalancedParenthesesValidation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('COUNT((posts.id) as total');
    }

    /**
     * Test para expresiones demasiado largas.
     */
    public function testTooLongExpressionValidation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        $longExpression = str_repeat('a', 501); // Más de 500 caracteres
        self::$orm->table('users')->selectRaw($longExpression);
    }

    /**
     * Test para detección de comentarios SQL.
     */
    public function testSQLCommentsDetection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('name /* comment */ as user_name');
    }

    /**
     * Test para detección de UNION attacks.
     */
    public function testUnionAttackDetection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('name UNION SELECT password FROM admin');
    }

    /**
     * Test para detección de funciones peligrosas.
     */
    public function testDangerousFunctionDetection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe SQL expression detected in selectRaw');

        self::$orm->table('users')->selectRaw('LOAD_FILE("/etc/passwd") as content');
    }

    /**
     * Test para funciones SQL permitidas.
     */
    public function testAllowedSQLFunctions(): void
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
            $this->assertInstanceOf(QueryBuilder::class, $result);
        }
    }

    /**
     * Test combinado: subconsulta compleja con múltiples condiciones.
     */
    public function testComplexSubqueryWithMultipleConditions(): void
    {
        $result = self::$orm->table('users')
            ->select(['id', 'name', 'email'])
            ->selectSubQuery(function (QueryBuilder $query): void {
                $query->select(['COUNT(*)'])
                    ->where('user_id', '=', 'users.id')
                    ->where('status', '=', 'published');
            }, 'published_posts_count')
            ->whereExists(function (QueryBuilder $query): void {
                $query->from('user_roles')
                    ->where('user_id', '=', 'users.id')
                    ->where('role', '=', 'author');
            })
            ->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['premium'])
            ->groupByRaw('YEAR(created_at), status');

        $this->assertInstanceOf(QueryBuilder::class, $result);
    }
}
