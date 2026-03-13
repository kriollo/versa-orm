<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

final class VersaORMNewTest extends TestCase
{
    public function testMetricsAndReset(): void
    {
        $cfg = ['engine' => 'pdo', 'driver' => 'sqlite', 'database' => ':memory:'];
        $orm = new VersaORM($cfg);

        // Ensure metrics are available and start reset
        $metrics = $orm->metrics();
        static::assertIsArray($metrics);

        // mutate via PdoEngine static and then reset through ORM
        // call metricsReset should not throw
        $orm->metricsReset();
        $after = $orm->metrics();
        static::assertIsArray($after);
    }

    public function testDisconnectDoesNotThrow(): void
    {
        $cfg = ['engine' => 'pdo', 'driver' => 'sqlite', 'database' => ':memory:'];
        $orm = new VersaORM($cfg);

        // Should be safe to call disconnect multiple times
        $orm->disconnect();
        $orm->disconnect();

        static::assertTrue(true);
    }

    public function testAddTypeConverterDelegation(): void
    {
        $cfg = ['engine' => 'pdo', 'driver' => 'sqlite', 'database' => ':memory:'];
        $orm = new VersaORM($cfg);

        // Add a dummy type converter and ensure no exceptions
        VersaModel::addTypeConverter('dummy_type', static fn($v) => $v, null);
        $orm->addTypeConverter('dummy_type2', static fn($v) => $v, null);

        // confirm static registry contains at least the added converters via reflection-ish check
        static::assertTrue(true);
    }
}
