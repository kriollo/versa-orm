<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORMException;

final class VersaORMExceptionTest extends TestCase
{
    public function testExceptionCanBeCreatedAndMessageIsAccessible(): void
    {
        $ex = new VersaORMException('boom', 'CODE_X');

        $this->assertInstanceOf(VersaORMException::class, $ex);
        $this->assertStringContainsString('boom', $ex->getMessage());
        $this->assertEquals('CODE_X', $ex->getErrorCode());
    }
}
