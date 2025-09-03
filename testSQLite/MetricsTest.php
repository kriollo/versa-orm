<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

class MetricsTest extends TestCase
{
    public function test_metrics_increment_queries(): void
    {
        $orm = self::$orm; // instancia compartida
        $m0 = $orm->metrics();
        static::assertIsArray($m0);
        $initial = (int) ($m0['queries'] ?? 0);

        // Ejecutar dos lecturas simples
        $orm->table('users')->count();
        $orm->table('users')->first();

        $m1 = $orm->metrics();
        static::assertIsArray($m1);
        $after = (int) ($m1['queries'] ?? 0);
        static::assertGreaterThanOrEqual(
            $initial + 2,
            $after,
            'El contador de queries debe incrementarse al menos por 2',
        );
    }
}
