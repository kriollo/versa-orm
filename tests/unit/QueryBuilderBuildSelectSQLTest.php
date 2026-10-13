<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

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

        static::assertIsArray($res);
        static::assertArrayHasKey('sql', $res);
        static::assertArrayHasKey('bindings', $res);
        static::assertStringContainsString('FROM `users`', $res['sql']);
        static::assertSame([], $res['bindings']);
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

        static::assertStringContainsString('FROM (SELECT id FROM users_inner) AS `u`', $res['sql']);
        static::assertStringContainsString('`u`.`id`, `u`.`name`', $res['sql']);
        static::assertSame([123], $res['bindings']);
    }

    public function testBuildSelectSqlWithJoinsAndWheresBindings(): void
    {
        $orm = new VersaORMStub();
        $qb = new QueryBuilder($orm, 'users');

        // Por la API real, no inyectando estado por reflexión: la forma interna que
        // inyectaba este test ('sql' + 'bindings' sueltos en wheres) sólo la entendía el
        // generador duplicado que se eliminó.
        $qb->joinRaw('INNER JOIN profiles ON profiles.user_id = users.id AND profiles.active = ?', [
            1,
        ])->whereRaw('users.id = ?', [42]);

        $ref = new \ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);

        static::assertStringContainsString('INNER JOIN profiles ON profiles.user_id = users.id', $res['sql']);
        static::assertStringContainsString('WHERE (users.id = ?)', $res['sql']);
        // Los bindings del JOIN van antes que los del WHERE, en el orden de los placeholders.
        static::assertSame([1, 42], $res['bindings']);
    }
}
