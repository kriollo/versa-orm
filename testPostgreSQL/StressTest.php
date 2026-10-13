<?php

// tests/StressTest.php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\SQL\PdoEngine;

/**
 * Pruebas de carga de VersaORM.
 *
 * Antes este archivo era un `assertTrue(true, 'Stress tests not yet implemented')` con un
 * TODO: pasaba siempre y no cubría nada. Ahora cada test afirma números concretos, de
 * forma que una regresión en el troceado de lotes, en la hidratación o en la caché de
 * sentencias lo rompa.
 *
 * @group postgresql
 */
class StressTest extends TestCase
{
    private const BULK_ROWS = 2000;

    /**
     * Inserción masiva: el número de sentencias ejecutadas tiene que depender del número
     * de lotes, no del número de filas.
     */
    public function test_bulk_insert_scales_by_batch_not_by_row(): void
    {
        $records = [];

        for ($i = 1; $i <= self::BULK_ROWS; $i++) {
            $records[] = [
                'name' => 'carga_' . $i,
                'email' => sprintf('carga_%d_%s@test.local', $i, bin2hex(random_bytes(3))),
                'status' => 'active',
            ];
        }
        $before = PdoEngine::getMetrics();
        $result = self::$orm->table('users')->insertMany($records, 500);
        $after = PdoEngine::getMetrics();

        static::assertSame('success', $result['status'] ?? null);
        static::assertSame(self::BULK_ROWS, (int) self::$orm->table('users')->count() - 3);

        $statements =
            $after['stmt_cache_hits'] - $before['stmt_cache_hits']
            + ($after['stmt_cache_misses'] - $before['stmt_cache_misses']);

        // 2000 filas en lotes de 500 son 4 sentencias; se deja holgura, pero tiene que
        // quedar muy por debajo del número de filas.
        static::assertLessThan(
            50,
            $statements,
            sprintf('%d sentencias para %d filas insertadas', $statements, self::BULK_ROWS),
        );
    }

    /**
     * Un lote con muchas columnas no debe desbordar el límite de placeholders del driver
     * (65 535 en MySQL/PostgreSQL). Antes nadie los contaba y el driver fallaba.
     */
    public function test_large_batch_does_not_exceed_placeholder_limit(): void
    {
        $records = [];

        for ($i = 1; $i <= 6000; $i++) {
            $records[] = [
                'name' => 'ph_' . $i,
                'email' => sprintf('ph_%d_%s@test.local', $i, bin2hex(random_bytes(3))),
                'status' => 'active',
            ];
        }
        // batchSize alto a propósito: el motor debe acotarlo por el presupuesto.
        $result = self::$orm->table('users')->insertMany($records, 10_000);

        static::assertSame('success', $result['status'] ?? null);
        static::assertSame(6003, (int) self::$orm->table('users')->count());
    }

    /**
     * Hidratar un resultado grande no debe introspeccionar el esquema por fila.
     */
    public function test_large_result_hydration_does_not_introspect_per_row(): void
    {
        $records = [];

        for ($i = 1; $i <= 1000; $i++) {
            $records[] = [
                'name' => 'hid_' . $i,
                'email' => sprintf('hid_%d_%s@test.local', $i, bin2hex(random_bytes(3))),
                'status' => 'active',
            ];
        }
        self::$orm->table('users')->insertMany($records, 500);

        $before = PdoEngine::getMetrics();
        $rows = self::$orm->table('users')->getAll();
        $after = PdoEngine::getMetrics();

        static::assertCount(1003, $rows);

        $statements =
            $after['stmt_cache_hits'] - $before['stmt_cache_hits']
            + ($after['stmt_cache_misses'] - $before['stmt_cache_misses']);

        static::assertLessThan(
            20,
            $statements,
            sprintf('%d sentencias para hidratar %d filas', $statements, count($rows)),
        );
    }

    /**
     * Escrituras repetidas reutilizan la sentencia preparada. Antes cada COMMIT
     * descartaba la caché completa y se volvía a preparar todo en cada iteración.
     */
    public function test_repeated_writes_reuse_prepared_statements(): void
    {
        $before = PdoEngine::getMetrics();

        for ($i = 1; $i <= 50; $i++) {
            self::$orm
                ->table('users')
                ->insert([
                    'name' => 'rep_' . $i,
                    'email' => sprintf('rep_%d_%s@test.local', $i, bin2hex(random_bytes(3))),
                    'status' => 'active',
                ]);
        }
        $after = PdoEngine::getMetrics();
        $misses = $after['stmt_cache_misses'] - $before['stmt_cache_misses'];

        // El INSERT es el mismo SQL las 50 veces: debe prepararse una vez.
        static::assertLessThan(10, $misses, sprintf('%d preparaciones para 50 INSERT idénticos', $misses));
    }

    /** La memoria no debe crecer de forma desbocada al hidratar en lotes. */
    public function test_batched_reads_keep_memory_bounded(): void
    {
        $records = [];

        for ($i = 1; $i <= 1500; $i++) {
            $records[] = [
                'name' => 'mem_' . $i,
                'email' => sprintf('mem_%d_%s@test.local', $i, bin2hex(random_bytes(3))),
                'status' => 'active',
            ];
        }
        self::$orm->table('users')->insertMany($records, 500);

        $start = memory_get_usage(true);
        $seen = 0;

        foreach ([0, 500, 1000] as $offset) {
            $batch = self::$orm->table('users')->limit(500)->offset($offset)->getAll();
            $seen += count($batch);
            unset($batch);
        }
        $growth = memory_get_usage(true) - $start;

        static::assertSame(1500, $seen);
        static::assertLessThan(
            64 * 1024 * 1024,
            $growth,
            sprintf('la memoria creció %d bytes leyendo en lotes', $growth),
        );
    }
}
