<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\ErrorHandler;
use VersaORM\VersaORMException;

/**
 * @group sqlite
 */
final class ErrorHandlerTest extends TestCase
{
    protected function tearDown(): void
    {
        // Limpiar estado global del ErrorHandler para evitar contaminación entre tests
        ErrorHandler::clearErrorLog();
        ErrorHandler::setDebugMode(false);
        ErrorHandler::setCustomHandler(null);
    }

    public function test_format_query_with_bindings(): void
    {
        $reflect = new ReflectionClass(ErrorHandler::class);
        $method = $reflect->getMethod('formatQuery');
        $method->setAccessible(true);

        $sql = 'SELECT * FROM users WHERE id = ? AND name = ?';
        $formatted = $method->invoke(null, $sql, [123, 'Alice']);

        self::assertIsString($formatted);
        self::assertStringContainsString("'Alice'", $formatted);
        self::assertStringContainsString('123', $formatted);
    }

    public function test_format_for_development_and_production(): void
    {
        $ex = new VersaORMException('fail', 'SOME_CODE', 'SELECT 1', [1], ['detail' => 'x']);
        $reflect = new ReflectionClass(ErrorHandler::class);
        $extract = $reflect->getMethod('extractErrorData');
        $extract->setAccessible(true);

        $err = $extract->invoke(null, $ex, ['user' => 'tester']);

        $dev = ErrorHandler::formatForDevelopment($err);
        self::assertIsString($dev);
        self::assertStringContainsString('VersaORM Error Details', $dev);

        $prod = ErrorHandler::formatForProduction($err);
        self::assertIsArray($prod);
        self::assertArrayHasKey('error', $prod);
        self::assertArrayHasKey('reference', $prod);
    }

    public function test_configure_and_logpath_and_wrap_calls_handler(): void
    {
        $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'versa_err_test_' . uniqid();
        // Ensure directory removed after
        @mkdir($tmp, 0755, true);

        ErrorHandler::configureFromVersaORM(['log_path' => $tmp, 'debug' => true]);

        self::assertTrue(ErrorHandler::isConfigured());
        self::assertTrue(ErrorHandler::isDebugMode());
        self::assertStringContainsString('versa_err_test_', (string) ErrorHandler::getLogPath());

        $called = false;
        ErrorHandler::setCustomHandler(function (array $data) use (&$called) {
            $called = true;
        });

        $ex = new VersaORMException('boom', 'E_TEST', 'SELECT 1', [], []);

        $this->expectException(\VersaORM\VersaORMException::class);
        // Capturar cualquier output generado por formatForDevelopment to avoid PHPUnit marking the test as risky
        ob_start();

        try {
            ErrorHandler::wrap(function () use ($ex) {
                throw $ex;
            }, ['ctx' => 'x']);
        } finally {
            $out = (string) ob_get_clean();
            // If debug output exists, ensure it contains the error header for sanity
            if ($out !== '') {
                self::assertStringContainsString('VersaORM Error Details', $out);
            }
            self::assertTrue($called, 'Custom handler should be invoked');
        }
    }

    public function testHandleExceptionAddsToErrorLog(): void
    {
        // Asegurar log limpio
        ErrorHandler::clearErrorLog();

        $ex = new VersaORMException('fail', 'TEST_CODE', 'SELECT 1', [], [], null, 0);

        $data = ErrorHandler::handleException($ex, ['extra' => 'context']);

        self::assertIsArray($data);
        $log = ErrorHandler::getErrorLog();
        self::assertNotEmpty($log);
        self::assertSame('TEST_CODE', $data['error']['error_code']);
    }
}
