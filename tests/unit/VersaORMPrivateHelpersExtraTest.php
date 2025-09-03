<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\VersaORM;

class VersaORMPrivateHelpersExtraTest extends TestCase
{
    public function testSafeParamsForLogTruncationAndArrays(): void
    {
        $orm = new VersaORM();
        $r = new \ReflectionClass($orm);
        $m = $r->getMethod('safeParamsForLog');
        $m->setAccessible(true);

        $long = str_repeat('x', 600);
        $params = ['a' => $long, 'b' => array_fill(0, 60, 'v')];
        $out = $m->invoke($orm, $params);

        $this->assertArrayHasKey('a', $out);
        $this->assertStringContainsString('…', $out['a']);
        $this->assertArrayHasKey('b', $out);
        $this->assertArrayHasKey('_truncated', $out['b']);
    }

    public function testExtractSqlStateWithPdoException(): void
    {
        $orm = new VersaORM();
        $r = new \ReflectionClass($orm);
        $m = $r->getMethod('extractSqlState');
        $m->setAccessible(true);

        $pdoEx = new \PDOException('err');
        // attach errorInfo as typical PDOException
        $pdoEx->errorInfo = ['HY000', '1', 'msg'];

        $state = $m->invoke($orm, $pdoEx);
        $this->assertSame('HY000', $state);
    }
}
