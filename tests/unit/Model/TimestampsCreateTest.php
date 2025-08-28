<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaModel;

/** @group sqlite */
final class TimestampsCreateTest extends TestCase
{
    public function test_insert_sets_created_and_updated_timestamps(): void
    {
        // Usar el ORM configurado por TestCase (createSchema se ejecuta en setUp)
        $model = VersaModel::dispense('test_timestamps');
        $model->name = 'foo';

        $id = $model->store();

        $this->assertNotNull($id);
        $row = self::$orm->exec('SELECT * FROM test_timestamps WHERE id = ?', [$id]);
        $this->assertIsArray($row);
        $this->assertNotEmpty($row);
        $record = $row[0];
        $this->assertArrayHasKey('created_at', $record);
        $this->assertArrayHasKey('updated_at', $record);
    }
}
