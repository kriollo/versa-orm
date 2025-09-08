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

        self::assertNotNull($id);
        $row = self::$orm->exec('SELECT * FROM test_timestamps WHERE id = ?', [$id]);
        self::assertIsArray($row);
        self::assertNotEmpty($row);
        $record = $row[0];
        self::assertArrayHasKey('created_at', $record);
        self::assertArrayHasKey('updated_at', $record);
    }
}
