<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;
use VersaORM\VersaORMException;

final class PdoEngineAdvancedErrorsTest extends TestCase
{
    public function test_set_operation_requires_two_queries()
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $e = new PdoEngine($cfg);

        $this->expectException(VersaORMException::class);
        $e->execute('advanced_sql', ['operation_type' => 'set_operation', 'set_type' => 'UNION', 'queries' => []]);
    }

    public function test_invalid_set_type_throws()
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $e = new PdoEngine($cfg);

        $this->expectException(VersaORMException::class);
        $e->execute('advanced_sql', ['operation_type' => 'set_operation', 'set_type' => 'BAD', 'queries' => [['sql' => 'SELECT 1'], ['sql' => 'SELECT 2']]]);
    }
}
