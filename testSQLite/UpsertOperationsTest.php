<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\QueryBuilder;

class UpsertOperationsTest extends TestCase
{
    public function test_upsert_insert_and_update(): void
    {
        $qb = new QueryBuilder(self::$orm, 'products');

        // Primero insertar
        $qb->upsert(['sku' => 'X001', 'name' => 'Widget', 'price' => 10.0, 'stock' => 5], ['sku']);
        $p = self::$orm->table('products')->find('X001', 'sku');
        static::assertNotNull($p);
        static::assertSame('Widget', $p->name);

        // Luego actualizar
        $qb->upsert(['sku' => 'X001', 'name' => 'Widget+', 'price' => 12.5, 'stock' => 10], ['sku']);
        $p2 = self::$orm->table('products')->find('X001', 'sku');
        static::assertSame('Widget+', $p2->name);
        static::assertSame(10, (int) $p2->stock);
    }
}
