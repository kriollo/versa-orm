<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\ErrorHandler;
use VersaORM\VersaORMException;

final class ErrorHandlerTest extends TestCase
{
    public function testHandleExceptionAddsToErrorLog(): void
    {
        // Asegurar log limpio
        ErrorHandler::clearErrorLog();

        $ex = new VersaORMException('fail', 'TEST_CODE', 'SELECT 1', [], [], null, 0);

        $data = ErrorHandler::handleException($ex, ['extra' => 'context']);

        $this->assertIsArray($data);
        $log = ErrorHandler::getErrorLog();
        $this->assertNotEmpty($log);
        $this->assertEquals('TEST_CODE', $data['error']['error_code']);
    }
}
