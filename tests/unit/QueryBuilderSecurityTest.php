<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

class VersaORMStub3 extends VersaORM
{
    public function __construct() {}

    public function executeQuery(string $action, array $params = [])
    {
        return [];
    }
}

/**
 * @group sqlite
 */
final class QueryBuilderSecurityTest extends TestCase
{
    private QueryBuilder $qb;

    protected function setUp(): void
    {
        $orm = new VersaORMStub3();
        $this->qb = new QueryBuilder($orm, 'users');
    }

    public function testIsSafeIdentifierValidAndInvalid(): void
    {
        $ref = new \ReflectionClass($this->qb);
        $m = $ref->getMethod('isSafeIdentifier');
        $m->setAccessible(true);

        static::assertTrue($m->invoke($this->qb, '*'));
        static::assertTrue($m->invoke($this->qb, 'users'));
        static::assertTrue($m->invoke($this->qb, 'users.name as author'));
        static::assertFalse($m->invoke($this->qb, 'users; DROP TABLE users'));
        static::assertFalse($m->invoke($this->qb, '1weird'));
    }

    public function testIsSQLFunctionDetectsAllowedFunctions(): void
    {
        $ref = new \ReflectionClass($this->qb);
        $m = $ref->getMethod('isSQLFunction');
        $m->setAccessible(true);

        static::assertTrue($m->invoke($this->qb, 'COUNT(*)'));
        static::assertTrue($m->invoke($this->qb, 'MAX(price)'));
        static::assertFalse($m->invoke($this->qb, 'BADFUNC(1; DROP TABLE)'));
        static::assertFalse($m->invoke($this->qb, 'SLEEP(10)'));
    }

    public function testIsSafeRawExpressionRejectsDangerousPatterns(): void
    {
        $ref = new \ReflectionClass($this->qb);
        $m = $ref->getMethod('isSafeRawExpression');
        $m->setAccessible(true);

        static::assertTrue($m->invoke($this->qb, 'SELECT id FROM users'));
        static::assertFalse($m->invoke($this->qb, 'SELECT * FROM users; DROP TABLE secret;'));
        static::assertFalse($m->invoke($this->qb, str_repeat('(', 600)));
    }
}
