<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

if (!class_exists('VersaORMStub')) {
    class VersaORMStub extends VersaORM
    {
        public function __construct()
        {
            // minimal stub: no real config
        }

        public function executeQuery(string $action, array $params = [])
        {
            // Not used by these tests
            return [];
        }
    }
}

/**
 * @group sqlite
 */
final class QueryBuilderBuildSelectSQLTest extends TestCase
{
    public function testBuildSelectSqlDefaultSelectsAndTable(): void
    {
        $orm = new VersaORMStub();
        $qb = new QueryBuilder($orm, 'users');

        $ref = new \ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);

        self::assertIsArray($res);
        self::assertArrayHasKey('sql', $res);
        self::assertArrayHasKey('bindings', $res);
        self::assertStringContainsString('FROM users', $res['sql']);
        self::assertSame([], $res['bindings']);
    }

    public function testBuildSelectSqlWithFromSubAndSelects(): void
    {
        $orm = new VersaORMStub();
        $qb = new QueryBuilder($orm, 'users');

        // Inject fromSub and selects via Reflection
        $ref = new \ReflectionClass($qb);
        $propFrom = $ref->getProperty('fromSub');
        $propFrom->setAccessible(true);
        $propFrom->setValue($qb, ['sql' => 'SELECT id FROM users_inner', 'bindings' => [123], 'alias' => 'u']);

        $propSelects = $ref->getProperty('selects');
        $propSelects->setAccessible(true);
        $propSelects->setValue($qb, ['u.id', 'u.name']);

        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);

        self::assertStringContainsString('FROM (SELECT id FROM users_inner) u', $res['sql']);
        self::assertStringContainsString('u.id, u.name', $res['sql']);
        self::assertSame([123], $res['bindings']);
    }

    public function testBuildSelectSqlWithJoinsAndWheresBindings(): void
    {
        $orm = new VersaORMStub();
        $qb = new QueryBuilder($orm, 'users');

        $ref = new \ReflectionClass($qb);

        // Add a join with a raw ON condition
        $joinsProp = $ref->getProperty('joins');
        $joinsProp->setAccessible(true);
        $joinsProp->setValue($qb, [
            [
                'type' => 'inner',
                'table' => 'profiles',
                'conditions' => [
                    [
                        'type' => 'raw',
                        'sql' => 'profiles.user_id = users.id AND profiles.active = ?',
                        'bindings' => [1],
                        'boolean' => 'AND',
                    ],
                ],
            ],
        ]);

        // Add where raw entry in the wheres
        $wheresProp = $ref->getProperty('wheres');
        $wheresProp->setAccessible(true);
        $wheresProp->setValue($qb, [
            ['sql' => 'users.id = ?', 'bindings' => [42]],
        ]);

        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);

        self::assertStringContainsString('INNER JOIN profiles', $res['sql']);
        self::assertStringContainsString('ON (profiles.user_id = users.id AND profiles.active = ?)', $res['sql']);
        self::assertStringContainsString('WHERE users.id = ?', $res['sql']);
        // Note: buildSelectSQL merges only fromSub and where bindings; join raw bindings are not merged here
        self::assertSame([42], $res['bindings']);
    }
}
