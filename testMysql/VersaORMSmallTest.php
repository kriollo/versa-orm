<?php

// tests/VersaORMSmallTest.php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\QueryBuilder;

require_once __DIR__ . '/TestCase.php';

/**
 * @group mysql
 */
class VersaORMSmallTest extends TestCase
{
    public function test_set_and_get_config_and_table(): void
    {
        $orm = self::$orm;
        $orig = $orm->getConfig();

        $orm->setConfig(array_merge($orig, ['custom_flag' => true]));
        $cfg = $orm->getConfig();
        self::assertArrayHasKey('custom_flag', $cfg);

        $qb = $orm->table('users');
        self::assertInstanceOf(QueryBuilder::class, $qb);
    }

    public function test_set_and_get_timezone(): void
    {
        $orm = self::$orm;
        $prev = date_default_timezone_get();
        $orm->setTimezone('UTC');
        self::assertSame('UTC', $orm->getTimezone());
        self::assertSame('UTC', date_default_timezone_get());
        // restore
        date_default_timezone_set($prev);
    }

    public function test_metrics_reset_and_disconnect(): void
    {
        $orm = self::$orm;
        $metrics = $orm->metrics();
        self::assertIsArray($metrics);

        // metricsReset should not throw and should reset internal state
        $orm->metricsReset();
        $orm->disconnect();

        // after disconnect metrics() should recreate engine and return array
        $metrics2 = $orm->metrics();
        self::assertIsArray($metrics2);
    }

    public function test_add_type_converter_and_execute_query_alias(): void
    {
        $orm = self::$orm;

        // Delegate addTypeConverter - ensure it doesn't throw
        $orm->addTypeConverter('test_conv', fn($v) => (string) $v, null);

        // executeQuery wrapper should proxy to exec/raw; use a simple select
        $res = $orm->executeQuery('raw', ['query' => 'SELECT 1 as one', 'bindings' => []]);
        self::assertNotNull($res);
    }
}
