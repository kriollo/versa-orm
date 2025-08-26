<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\VersaModel;
use VersaORM\VersaORM;

class TestModel extends VersaModel
{
    protected string $table = 'custom_table';
}

class VersaModelBehaviorTest extends TestCase
{
    public function testTableNameFromStaticProperty(): void
    {
        $this->assertSame('custom_table', TestModel::tableName());
    }

    public function testSetAndGetGlobalOrm(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaModel::setORM($orm);
        $this->assertSame($orm, VersaModel::getGlobalORM());
        VersaModel::setORM(null);
    }

    public function testLoadInstanceFromArrayLoadsAttributesAndRelations(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaModel::setORM($orm);

        $m = new TestModel('custom_table', $orm);

        $data = [
            'id' => 1,
            'name' => 'Bob',
            'meta' => json_encode(['a' => 1]),
        ];

        $m->loadInstance($data);
        $this->assertSame('Bob', $m->name);
        $this->assertTrue(isset($m->id));
    }
}
