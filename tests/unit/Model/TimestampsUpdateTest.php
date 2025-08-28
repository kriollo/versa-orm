<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaModel;

/** @group sqlite */
final class TimestampsUpdateTest extends TestCase
{
    public function test_update_changes_updated_at(): void
    {
        $model = VersaModel::dispense('test_timestamps_update');
        $model->name = 'initial';

        $id = $model->store();
        $this->assertNotNull($id);

        $rowBefore = self::$orm->exec('SELECT * FROM test_timestamps_update WHERE id = ?', [$id]);
        $this->assertNotEmpty($rowBefore);
        $before = $rowBefore[0]['updated_at'] ?? null;
        // small sleep to ensure timestamp difference
        usleep(50000);
        $model->name = 'changed';
        $model->store();

        $rowAfter = self::$orm->exec('SELECT * FROM test_timestamps_update WHERE id = ?', [$id]);
        $this->assertNotEmpty($rowAfter);
        $after = $rowAfter[0]['updated_at'] ?? null;

        $this->assertNotNull($before);
        $this->assertNotNull($after);
        $this->assertNotEquals($before, $after, 'updated_at should change after update');
    }
}
