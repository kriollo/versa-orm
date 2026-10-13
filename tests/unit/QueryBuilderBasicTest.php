<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
final class QueryBuilderBasicTest extends TestCase
{
    public function test_build_select_sql_basic(): void
    {
        // Crear una instancia mínima de VersaORM compatible con QueryBuilder
        $orm = $this->createMock(VersaORM::class);

        $qb = new QueryBuilder($orm, 'users');

        $qb->select(['id', 'name'])->where('active', '=', 1)->limit(10)->offset(5);

        // Acceder al método privado buildSelectSQL mediante reflexión
        $ref = new ReflectionClass($qb);
        $method = $ref->getMethod('buildSelectSQL');
        $method->setAccessible(true);

        $result = $method->invoke($qb);

        static::assertIsArray($result);
        static::assertArrayHasKey('sql', $result);
        static::assertArrayHasKey('bindings', $result);

        $sql = $result['sql'];
        $bindings = $result['bindings'];

        // Identificadores citados, y LIMIT/OFFSET ya forman parte del SQL generado:
        // antes buildSelectSQL los descartaba en silencio.
        static::assertStringContainsString('SELECT `id`, `name`', $sql);
        static::assertStringContainsString('FROM `users`', $sql);
        static::assertStringContainsString('WHERE `active` = ?', $sql);
        static::assertStringContainsString('LIMIT 10', $sql);
        static::assertStringContainsString('OFFSET 5', $sql);
        static::assertSame([1], $bindings);
    }
}
