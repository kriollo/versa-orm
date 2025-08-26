<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

final class VersaModelIntegrationTest extends TestCase
{
    private VersaORM $orm;

    public function setUp(): void
    {
        // Configurar ORM para usar sqlite in-memory
        $this->orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaModel::setORM($this->orm);
    }

    public function test_store_and_load_basic()
    {
        $m = VersaModel::dispense('users');
        $m->name = 'Bob';
        $id = $m->store();

        $this->assertIsInt($id);

        $loaded = VersaModel::load('users', $id);
        $this->assertSame('Bob', $loaded->name);
    }

    public function test_upsert_and_replace()
    {
        $m = VersaModel::dispense('items');
        $m->sku = 'X1';
        $m->qty = 5;
        $m->store();

        // Update
        $m2 = VersaModel::dispense('items');
        $m2->sku = 'X1';
        $m2->qty = 10;
        $m2->upsert(['sku']);

        $found = VersaModel::findOne('items', ['sku' => 'X1']);
        $this->assertNotNull($found);
        $this->assertEquals(10, $found->qty);
    }
}
