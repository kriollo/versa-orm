<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORMException;

final class VersaORMExceptionTest extends TestCase
{
    public function testExceptionCanBeCreatedAndMessageIsAccessible(): void
    {
        $ex = new VersaORMException('boom', 'CODE_X');

        static::assertInstanceOf(VersaORMException::class, $ex);
        static::assertStringContainsString('boom', $ex->getMessage());
        static::assertSame('CODE_X', $ex->getErrorCode());
    }
}
