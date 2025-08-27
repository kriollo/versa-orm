<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
final class VersaModelStoreLoadTest extends TestCase
{
    public function testStoreLoadAndExport(): void
    {
        // Preparar ORM en memoria
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaModel::setORM($orm);

        // Crear tabla mínima
        $orm->exec('CREATE TABLE vm_test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER)');

        // Crear modelo, asignar datos y almacenar
        $m = VersaModel::dispense('vm_test');
        $m->name = 'Alice';
        $m->age = 30;

        $id = $m->store();
        $this->assertNotNull($id, 'store() should return an id or null');

        // Cargar via static load
        $loaded = VersaModel::load('vm_test', $id);
        $this->assertInstanceOf(VersaModel::class, $loaded);

        $data = $loaded->export();
        $this->assertIsArray($data);
        $this->assertSame('Alice', $data['name']);
        $this->assertEquals(30, $data['age']);

        // Actualizar y guardar
        $loaded->age = 31;
        $loaded->store();

        $reloaded = VersaModel::load('vm_test', $id);
        $this->assertEquals(31, $reloaded->getAttribute('age'));
    }
}
