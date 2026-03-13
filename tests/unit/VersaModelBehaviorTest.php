<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\VersaModel;
use VersaORM\VersaORM;

if (!class_exists('VersaORM\Tests\Unit\TestModelBehavior')) {
    class TestModelBehavior extends VersaModel
    {
        protected string $table = 'custom_table';

        public function __construct(?string $tableName = null, ?VersaORM $orm = null)
        {
            parent::__construct($tableName ?? $this->table, $orm);
        }

        public static function tableName(): string
        {
            return 'custom_table';
        }
    }
}

class VersaModelBehaviorTest extends TestCase
{
    public function testTableNameFromStaticProperty(): void
    {
        static::assertSame('custom_table', TestModelBehavior::tableName());
    }

    public function testSetAndGetGlobalOrm(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaModel::setORM($orm);
        static::assertSame($orm, VersaModel::getGlobalORM());
        VersaModel::setORM(null);
    }

    public function testLoadInstanceFromArrayLoadsAttributesAndRelations(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaModel::setORM($orm);

        $m = new TestModelBehavior(null, $orm);

        $data = [
            'id' => 1,
            'name' => 'Bob',
            'meta' => json_encode(['a' => 1]),
        ];

        $m->loadInstance($data);
        static::assertSame('Bob', $m->name);
        static::assertTrue(isset($m->id));
    }
}
