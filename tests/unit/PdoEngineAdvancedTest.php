<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\SQL\PdoEngine;

class PdoEngineAdvancedTest extends TestCase
{
    public function testExplainPlanGeneratesSql(): void
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $e = new PdoEngine($cfg);

        $ops = [['method' => 'get', 'table' => 'users', 'select' => ['*']]];
        $res = $e->execute('explain_plan', ['operations' => $ops]);
        $this->assertIsArray($res);
        $this->assertArrayHasKey('generated_sql', $res);
    }

    public function testQueryPlanExecutes(): void
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $e = new PdoEngine($cfg);

        $ops = [['method' => 'get', 'table' => 'users', 'select' => ['*']]];
        $res = $e->execute('query_plan', ['operations' => $ops]);
        $this->assertIsArray($res);
    }

    public function testAdvancedSqlUnionRequiresTwoQueries(): void
    {
        $this->expectException(\VersaORM\VersaORMException::class);
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $e = new PdoEngine($cfg);

        $e->execute('advanced_sql', [
            'operation_type' => 'set_operation',
            'set_type' => 'UNION',
            'queries' => [['sql' => 'SELECT 1']],
        ]);
    }
}
