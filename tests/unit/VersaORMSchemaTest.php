<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\VersaORM;

class VersaORMSchemaTest extends TestCase
{
    public function testCreateTableWithDefaultsAndIndexes(): void
    {
        $orm = new VersaORM();
        $orm->setConfig(['driver' => 'sqlite', 'database' => ':memory:']);

        // Should not throw and should create SQL for table
        $orm->schemaCreate(
            'users',
            [
                ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
                ['name' => 'active', 'type' => 'BOOLEAN', 'default' => true],
                ['name' => 'created_at', 'type' => 'TEXT', 'default' => 'CURRENT_TIMESTAMP'],
            ],
            [
                'if_not_exists' => true,
                'indexes' => [
                    ['name' => 'idx_users_active', 'columns' => ['active']],
                ],
            ],
        );

        $this->assertTrue(true);
    }

    public function testInvalidIndexNameThrows(): void
    {
        $orm = new VersaORM();
        $orm->setConfig(['driver' => 'sqlite', 'database' => ':memory:']);

        $this->expectException(\VersaORM\VersaORMException::class);

        // Index name with space should be rejected by assertSafeIdentifier
        $orm->schemaCreate(
            't2',
            [
                ['name' => 'id', 'type' => 'INTEGER', 'primary' => true],
            ],
            [
                'indexes' => [
                    ['name' => 'bad name', 'columns' => ['id']],
                ],
            ],
        );
    }
}
