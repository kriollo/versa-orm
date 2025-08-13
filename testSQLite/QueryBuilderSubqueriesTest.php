<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

/**
 * Tests para subconsultas y expresiones raw en QueryBuilder (versión SQLite, lógica agnóstica del driver).
 */
class QueryBuilderSubqueriesTest extends TestCase
{
    private QueryBuilder $queryBuilder;

    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm          = $this->createMock(VersaORM::class);
        $this->queryBuilder = new QueryBuilder($this->orm, 'users');
    }

    public function testSelectRawWithSafeExpressions(): void
    {
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->selectRaw('COUNT(*) as total_users'));
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->selectRaw('UPPER(name) as upper_name', ['test']));
    }

    public function testSelectRawWithUnsafeExpressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('name; DROP TABLE users; --');
    }

    public function testSelectRawWithEmptyExpression(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('');
    }

    public function testOrderByRawWithSafeExpressions(): void
    {
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['active']));
    }

    public function testOrderByRawWithUnsafeExpressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->orderByRaw('name; DELETE FROM users WHERE 1=1; --');
    }

    public function testGroupByRawWithSafeExpressions(): void
    {
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->groupByRaw('strftime("%Y", created_at)'));
    }

    public function testGroupByRawWithUnsafeExpressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->groupByRaw('name UNION SELECT password FROM admin_users');
    }

    public function testWhereRawWithSafeExpressions(): void
    {
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereRaw('age > ? AND status = ?', [18, 'active']));
    }

    public function testWhereRawWithUnsafeExpressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->whereRaw('1=1; DROP TABLE users; --');
    }

    public function testSelectSubQueryWithClosure(): void
    {
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->selectSubQuery(static function (QueryBuilder $q): void {
            $q->select(['COUNT(*)'])->where('user_id', '=', 'users.id');
        }, 'posts_count'));
    }

    public function testSelectSubQueryWithInvalidAlias(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectSubQuery(static function (QueryBuilder $q): void {
            $q->select(['COUNT(*)']);
        }, 'invalid--alias');
    }

    public function testWhereSubQueryWithValidOperators(): void
    {
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereSubQuery('id', 'IN', static function (QueryBuilder $q): void {
            $q->select(['user_id'])->where('status', '=', 'active');
        }));
    }

    public function testWhereSubQueryWithInvalidOperator(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->whereSubQuery('id', 'LIKE', static function (QueryBuilder $q): void {
            $q->select(['user_id']);
        });
    }

    public function testWhereSubQueryWithInvalidColumn(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->whereSubQuery('id; DROP TABLE users', '=', static function (QueryBuilder $q): void {
            $q->select(['user_id']);
        });
    }

    public function testWhereExists(): void
    {
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereExists(static function (QueryBuilder $q): void {
            $q->from('posts')->where('user_id', '=', 'users.id');
        }));
    }

    public function testWhereNotExists(): void
    {
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereNotExists(static function (QueryBuilder $q): void {
            $q->from('banned_users')->where('user_id', '=', 'users.id');
        }));
    }

    public function testBuildSubQueryWithExistingQueryBuilder(): void
    {
        $sub = new QueryBuilder($this->orm, 'posts');
        $sub->select(['user_id'])->where('status', '=', 'published');
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereSubQuery('id', 'IN', $sub));
    }

    public function testBuildSubQueryWithInvalidType(): void
    {
        $this->expectException(VersaORMException::class);
        $ref = new ReflectionClass($this->queryBuilder);
        $m   = $ref->getMethod('buildSubQuery');
        $m->setAccessible(true);
        $m->invoke($this->queryBuilder, 'invalid_type');
    }

    public function testUnbalancedParenthesesValidation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('COUNT((posts.id) as total');
    }

    public function testTooLongExpressionValidation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw(str_repeat('a', 501));
    }

    public function testSQLCommentsDetection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('name /* comment */ as user_name');
    }

    public function testUnionAttackDetection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('name UNION SELECT password FROM admin');
    }

    public function testDangerousFunctionDetection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('LOAD_FILE("/etc/passwd") as content');
    }

    public function testAllowedSQLFunctions(): void
    {
        foreach (
            [
                'COUNT(*)',
                'SUM(amount)',
                'MAX(created_at)',
                'MIN(price)',
                'UPPER(name)',
                'LOWER(email)',
            ] as $fn
        ) {
            self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->selectRaw($fn . ' as result'));
        }
    }

    public function testComplexSubqueryWithMultipleConditions(): void
    {
        self::assertInstanceOf(
            QueryBuilder::class,
            $this->queryBuilder
                ->select(['id', 'name'])
                ->selectSubQuery(static function (QueryBuilder $q): void {
                    $q->select(['COUNT(*)'])
                        ->where('user_id', '=', 'users.id')
                        ->where('status', '=', 'published')
                    ;
                }, 'published_posts_count')
                ->whereExists(static function (QueryBuilder $q): void {
                    $q->from('user_roles')->where('user_id', '=', 'users.id');
                })
                ->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['premium'])
                ->groupByRaw('status'),
        );
    }
}
