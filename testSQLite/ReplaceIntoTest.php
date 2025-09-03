<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\QueryBuilder;

class ReplaceIntoTest extends TestCase
{
    public function test_replace_into_emulation(): void
    {
        $qb = new QueryBuilder(self::$orm, 'products');

        // Insert inicial
        $qb->replaceInto(['sku' => 'R001', 'name' => 'Initial', 'price' => 9.99, 'stock' => 1]);
        $p = self::$orm->table('products')->find('R001', 'sku');
        static::assertSame('Initial', $p->name);

        // Reemplazo que en SQLite debe emular UPSERT sin borrar
        $qb->replaceInto(['sku' => 'R001', 'name' => 'Updated', 'price' => 11.11, 'stock' => 2]);
        $p2 = self::$orm->table('products')->find('R001', 'sku');
        static::assertSame('Updated', $p2->name);
        static::assertSame(2, (int) $p2->stock);
    }
}
