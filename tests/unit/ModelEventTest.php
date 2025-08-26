<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\ModelEvent;

/**
 * @group sqlite
 */
final class ModelEventTest extends TestCase
{
    public function testConstructAndCancel(): void
    {
        $model = new stdClass();
        $ev = new ModelEvent($model, ['a' => 1], ['b' => 2]);

        $this->assertSame($model, $ev->model);
        $this->assertEquals(['a' => 1], $ev->original);
        $this->assertEquals(['b' => 2], $ev->changes);
        $this->assertFalse($ev->cancel);

        $ev->cancel('not allowed');
        $this->assertTrue($ev->cancel);
        $this->assertEquals('not allowed', $ev->error);
    }
}
