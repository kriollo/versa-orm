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

        $this->assertIsArray($res);
        $this->assertArrayHasKey('sql', $res);
        $this->assertArrayHasKey('bindings', $res);
        $this->assertStringContainsString('FROM users', $res['sql']);
        $this->assertEquals([], $res['bindings']);
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

        $this->assertStringContainsString('FROM (SELECT id FROM users_inner) u', $res['sql']);
        $this->assertStringContainsString('u.id, u.name', $res['sql']);
        $this->assertEquals([123], $res['bindings']);
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
                    ['type' => 'raw', 'sql' => 'profiles.user_id = users.id AND profiles.active = ?', 'bindings' => [1], 'boolean' => 'AND'],
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

        $this->assertStringContainsString('INNER JOIN profiles', $res['sql']);
        $this->assertStringContainsString('ON (profiles.user_id = users.id AND profiles.active = ?)', $res['sql']);
        $this->assertStringContainsString('WHERE users.id = ?', $res['sql']);
        // Note: buildSelectSQL merges only fromSub and where bindings; join raw bindings are not merged here
        $this->assertEquals([42], $res['bindings']);
    }
}
