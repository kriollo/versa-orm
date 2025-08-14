<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\QueryBuilder;
use VersaORM\VersaORMException;

/**
 * Casos de error adicionales para operaciones de conjuntos en PostgreSQL.
 */
class SetOperationsErrorTest extends TestCase
{
    public function testSetOperationTooFewQueries(): void
    {
        $this->expectException(VersaORMException::class);
        $qb = new QueryBuilder(self::$orm, 'users');
        // Forzamos acceso a método union() pasando sólo una consulta ya compilada bajo-level
        $qb->union([
            ['sql' => 'SELECT id FROM users', 'bindings' => []],
        ]);
    }

    public function testSetOperationInvalidTypeViaHack(): void
    {
        // Simulamos llamada directa al método protegido executeAdvancedSQL mediante reflexión para inyectar set_type inválido
        $this->expectException(VersaORMException::class);
        $qb = new QueryBuilder(self::$orm, 'users');
        $ref = new \ReflectionClass($qb);
        $method = $ref->getMethod('executeAdvancedSQL');
        $method->setAccessible(true);
        $payload = [
            'operation_type' => 'set_operation',
            'set_type' => 'UNION PLUS',
            'queries' => [
                ['sql' => 'SELECT id FROM users', 'bindings' => []],
                ['sql' => 'SELECT id FROM users', 'bindings' => []],
            ],
        ];
        $method->invoke($qb, $payload);
    }
}
