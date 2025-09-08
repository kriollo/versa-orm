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

        self::assertSame($model, $ev->model);
        self::assertSame(['a' => 1], $ev->original);
        self::assertSame(['b' => 2], $ev->changes);
        self::assertFalse($ev->cancel);

        $ev->cancel('not allowed');
        self::assertTrue($ev->cancel);
        self::assertSame('not allowed', $ev->error);
    }
}
