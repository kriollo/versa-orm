<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\ErrorHandler;
use VersaORM\VersaORMException;

/**
 * @group sqlite
 */
final class ErrorHandlerFormatTest extends TestCase
{
    public function setUp(): void
    {
        // ensure clean state
        ErrorHandler::clearErrorLog();
        ErrorHandler::setDebugMode(true);
    }

    public function test_handle_exception_format_and_wrap_callable(): void
    {
        $ex = new VersaORMException('Test message', 'TEST_CODE', 'SELECT 1', [1], [], null);

        $errorData = ErrorHandler::handleException($ex, ['test' => true]);
        self::assertIsArray($errorData);

        // formatForDevelopment expects the array produced by handleException
        $out = ErrorHandler::formatForDevelopment($errorData);
        self::assertIsString($out);
        self::assertStringContainsString('Test message', $out);

        // log should have at least one entry
        $log = ErrorHandler::getErrorLog();
        self::assertNotEmpty($log);

        // wrap should accept a callable and return its result
        $result = ErrorHandler::wrap(fn() => 'ok', ['ctx' => 1]);
        self::assertSame('ok', $result);
    }
}
