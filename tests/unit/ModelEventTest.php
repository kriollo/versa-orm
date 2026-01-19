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

        static::assertSame($model, $ev->model);
        static::assertSame(['a' => 1], $ev->original);
        static::assertSame(['b' => 2], $ev->changes);
        static::assertFalse($ev->cancel);

        $ev->cancel('not allowed');
        static::assertTrue($ev->cancel);
        static::assertSame('not allowed', $ev->error);
    }
}
