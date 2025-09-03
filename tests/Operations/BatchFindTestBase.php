<?php

declare(strict_types=1);

namespace VersaORM\Tests\Operations;

use VersaORM\VersaModel;

/**
 * Trait con tests compartidos para VersaModel::findInBatches.
 *
 * Escenarios cubiertos:
 *  - Procesamiento básico en múltiples lotes
 *  - Procesamiento con condición y bindings
 *  - Tabla vacía (no debe invocar callback)
 *  - Tamaño de lote mayor al total (una sola invocación)
 */
trait BatchFindTestBase
{
    public function testFindInBatchesBasic(): void
    {
        $batches = [];
        $invocations = 0;
        VersaModel::findInBatches(
            'users',
            function (array $models) use (&$batches, &$invocations): void {
                $invocations++;
                $batches[] = array_map(static function (VersaModel $m): int {
                    return (int) $m->id;
                }, $models);
            },
            2,
        );

        self::assertSame(2, $invocations);
        self::assertCount(2, $batches);
        self::assertSame([1, 2], $batches[0]);
        self::assertSame([3], $batches[1]);
        $all = array_merge(...$batches);
        sort($all);
        self::assertSame([1, 2, 3], $all);
    }

    public function testFindInBatchesWithCondition(): void
    {
        // status='active' => Alice(id 1), Charlie(id 3)
        $ids = [];
        $invocations = 0;

        VersaModel::findInBatches(
            'users',
            function (array $models) use (&$ids, &$invocations): void {
                $invocations++;
                foreach ($models as $m) {
                    $ids[] = (int) $m->id;
                }
            },
            1,
            'status = ?',
            ['active'],
        ); // batchSize=1 -> 2 invocaciones

        sort($ids);
        self::assertSame([1, 3], $ids);
        self::assertSame(2, $invocations, 'Debe invocarse dos veces el callback con batchSize=1 y 2 registros.');
    }

    public function testFindInBatchesOnEmptyResult(): void
    {
        $called = false;
        VersaModel::findInBatches(
            'users',
            function () use (&$called): void {
                $called = true;
            },
            10,
            'id < 0',
        ); // condición imposible => conjunto vacío
        self::assertFalse($called);
    }

    public function testFindInBatchesWithLargeBatchSize(): void
    {
        $count = 0;
        $ids = [];
        VersaModel::findInBatches(
            'users',
            function (array $models) use (&$count, &$ids): void {
                $count++;
                foreach ($models as $m) {
                    $ids[] = (int) $m->id;
                }
            },
            50,
        ); // batchSize > total

        sort($ids);
        self::assertSame([1, 2, 3], $ids);
        self::assertSame(1, $count, 'Solo debe procesarse un lote cuando batchSize excede el total.');
    }
}
