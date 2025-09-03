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
    private null|QueryBuilder $queryBuilder = null;

    private null|VersaORM $orm = null;

    protected function setUp(): void
    {
        $this->orm = $this->createMock(VersaORM::class);
        $this->queryBuilder = new QueryBuilder($this->orm, 'users');
    }

    public function test_select_raw_with_safe_expressions(): void
    {
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->selectRaw('COUNT(*) as total_users'));
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->selectRaw('UPPER(name) as upper_name', [
            'test',
        ]));
    }

    public function test_select_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('name; DROP TABLE users; --');
    }

    public function test_select_raw_with_empty_expression(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('');
    }

    public function test_order_by_raw_with_safe_expressions(): void
    {
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', [
            'active',
        ]));
    }

    public function test_order_by_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->orderByRaw('name; DELETE FROM users WHERE 1=1; --');
    }

    public function test_group_by_raw_with_safe_expressions(): void
    {
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->groupByRaw('strftime("%Y", created_at)'));
    }

    public function test_group_by_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->groupByRaw('name UNION SELECT password FROM admin_users');
    }

    public function test_where_raw_with_safe_expressions(): void
    {
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereRaw('age > ? AND status = ?', [
            18,
            'active',
        ]));
    }

    public function test_where_raw_with_unsafe_expressions(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->whereRaw('1=1; DROP TABLE users; --');
    }

    public function test_select_sub_query_with_closure(): void
    {
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->selectSubQuery(
            static function (QueryBuilder $q): void {
                $q->select(['COUNT(*)'])->where('user_id', '=', 'users.id');
            },
            'posts_count',
        ));
    }

    public function test_select_sub_query_with_invalid_alias(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectSubQuery(static function (QueryBuilder $q): void {
            $q->select(['COUNT(*)']);
        }, 'invalid--alias');
    }

    public function test_where_sub_query_with_valid_operators(): void
    {
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereSubQuery(
            'id',
            'IN',
            static function (QueryBuilder $q): void {
                $q->select(['user_id'])->where('status', '=', 'active');
            },
        ));
    }

    public function test_where_sub_query_with_invalid_operator(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->whereSubQuery('id', 'LIKE', static function (QueryBuilder $q): void {
            $q->select(['user_id']);
        });
    }

    public function test_where_sub_query_with_invalid_column(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->whereSubQuery('id; DROP TABLE users', '=', static function (QueryBuilder $q): void {
            $q->select(['user_id']);
        });
    }

    public function test_where_exists(): void
    {
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereExists(static function (QueryBuilder $q): void {
            $q->from('posts')->where('user_id', '=', 'users.id');
        }));
    }

    public function test_where_not_exists(): void
    {
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereNotExists(static function (QueryBuilder $q): void {
            $q->from('banned_users')->where('user_id', '=', 'users.id');
        }));
    }

    public function test_build_sub_query_with_existing_query_builder(): void
    {
        $sub = new QueryBuilder($this->orm, 'posts');
        $sub->select(['user_id'])->where('status', '=', 'published');
        static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->whereSubQuery('id', 'IN', $sub));
    }

    public function test_build_sub_query_with_invalid_type(): void
    {
        $this->expectException(VersaORMException::class);
        $ref = new ReflectionClass($this->queryBuilder);
        $m = $ref->getMethod('buildSubQuery');
        $m->setAccessible(true);
        $m->invoke($this->queryBuilder, 'invalid_type');
    }

    public function test_unbalanced_parentheses_validation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('COUNT((posts.id) as total');
    }

    public function test_too_long_expression_validation(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw(str_repeat('a', 501));
    }

    public function test_sql_comments_detection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('name /* comment */ as user_name');
    }

    public function test_union_attack_detection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('name UNION SELECT password FROM admin');
    }

    public function test_dangerous_function_detection(): void
    {
        $this->expectException(VersaORMException::class);
        $this->queryBuilder->selectRaw('LOAD_FILE("/etc/passwd") as content');
    }

    public function test_allowed_sql_functions(): void
    {
        foreach ([
            'COUNT(*)',
            'SUM(amount)',
            'MAX(created_at)',
            'MIN(price)',
            'UPPER(name)',
            'LOWER(email)',
        ] as $fn) {
            static::assertInstanceOf(QueryBuilder::class, $this->queryBuilder->selectRaw($fn . ' as result'));
        }
    }

    public function test_complex_subquery_with_multiple_conditions(): void
    {
        static::assertInstanceOf(
            QueryBuilder::class,
            $this->queryBuilder
                ->select(['id', 'name'])
                ->selectSubQuery(static function (QueryBuilder $q): void {
                    $q->select(['COUNT(*)'])->where('user_id', '=', 'users.id')->where('status', '=', 'published');
                }, 'published_posts_count')
                ->whereExists(static function (QueryBuilder $q): void {
                    $q->from('user_roles')->where('user_id', '=', 'users.id');
                })
                ->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['premium'])
                ->groupByRaw('status'),
        );
    }
}
