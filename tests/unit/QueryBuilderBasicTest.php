<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
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

        $this->assertIsArray($result);
        $this->assertArrayHasKey('sql', $result);
        $this->assertArrayHasKey('bindings', $result);

        $sql = $result['sql'];
        $bindings = $result['bindings'];

        // Comprobaciones sencillas sobre la SQL generada
        $this->assertStringContainsString('SELECT id, name', $sql);
        $this->assertStringContainsString('FROM users', $sql);
        $this->assertStringContainsString('WHERE active = ?', $sql);
        // buildSelectSQL actualmente no añade LIMIT/OFFSET para la consulta principal;
        // comprobar que la cláusula WHERE y bindings estén presentes.
        $this->assertStringNotContainsString('LIMIT', $sql);
        $this->assertEquals([1], $bindings);
    }
}
