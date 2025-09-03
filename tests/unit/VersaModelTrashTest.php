<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

final class VersaModelTrashTest extends TestCase
{
    public function setUp(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaModel::setORM($orm);
    }

    public function test_trash_and_load_returns_null()
    {
        $m = VersaModel::dispense('trash_test');
        $m->name = 'T1';
        $id = $m->store();

        static::assertIsInt($id);

        $m->trash();

        $loaded = VersaModel::load('trash_test', $id);
        static::assertNull($loaded);
    }
}
