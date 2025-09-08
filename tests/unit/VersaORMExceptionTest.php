<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORMException;

final class VersaORMExceptionTest extends TestCase
{
    public function testExceptionCanBeCreatedAndMessageIsAccessible(): void
    {
        $ex = new VersaORMException('boom', 'CODE_X');

        self::assertInstanceOf(VersaORMException::class, $ex);
        self::assertStringContainsString('boom', $ex->getMessage());
        self::assertSame('CODE_X', $ex->getErrorCode());
    }
}
