<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\VersaORM;

class VersaORMFreezeTest extends TestCase
{
    public function testGlobalFreezeBlocksSchemaCreate(): void
    {
        $orm = new VersaORM();
        $orm->setConfig(['driver' => 'sqlite', 'database' => ':memory:']);
        $orm->freeze(true);

        $this->expectException(\VersaORM\VersaORMException::class);
        $orm->schemaCreate('t', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
        ]);
    }

    public function testRawDDLBlockedByFreeze(): void
    {
        $orm = new VersaORM();
        $orm->setConfig(['driver' => 'sqlite', 'database' => ':memory:']);
        $orm->freeze(true);

        $this->expectException(\VersaORM\VersaORMException::class);
        $orm->exec('CREATE TABLE x (id INTEGER)');
    }

    public function testFreezeModelAndIsModelFrozen(): void
    {
        $orm = new VersaORM();
        $orm->setConfig(['driver' => 'sqlite', 'database' => ':memory:']);
        $orm->freezeModel('User', true);
        static::assertTrue($orm->isModelFrozen('User'));

        $this->expectException(\InvalidArgumentException::class);
        $orm->isModelFrozen('');
    }
}
