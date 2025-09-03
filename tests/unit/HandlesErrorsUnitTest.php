<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\ErrorHandler;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaORMException;

require_once __DIR__ . '/../../vendor/autoload.php';

// Modelo mínimo para exponer métodos protegidos del trait para pruebas
class MinimalModelForHandleErrors
{
    use HandlesErrors;

    public array $attributes = [];

    public function getTable(): string
    {
        return 'minimal';
    }

    // métodos dummy que podrían lanzar
    public function save()
    {
        throw new VersaORMException('Simulated save error', 'SIM_SAVE_ERR');
    }

    public static function find($id)
    {
        return null;
    }

    public function exists(): bool
    {
        return false;
    }
}

class HandlesErrorsUnitTest extends TestCase
{
    public function setUp(): void
    {
        ErrorHandler::clearErrorLog();
        ErrorHandler::setDebugMode(false);
        // set a predictable config
        MinimalModelForHandleErrors::configureErrorHandling([
            'throw_on_error' => false,
            'format_for_api' => false,
            'include_suggestions' => true,
        ]);
    }

    public function testHandleModelErrorRegistersLastErrorAndReturnsNullWhenNotThrowing(): void
    {
        $m = new MinimalModelForHandleErrors();

        // call safeSave which will use withErrorHandling and capture the exception
        $result = $m->safeSave();

        static::assertNull($result, 'safeSave should return null when throw_on_error is false');
        static::assertTrue($m->hasError(), 'Model should have lastError set');
        static::assertSame('Simulated save error', $m->getLastErrorMessage());
    }

    public function testFormatErrorForApiIncludesDebugWhenDebugMode(): void
    {
        ErrorHandler::setDebugMode(true);

        $m = new MinimalModelForHandleErrors();

        // trigger error
        $m->safeSave();

        $error = $m->getLastError();
        static::assertIsArray($error);

        // format for api should include debug block when debug mode is on
        // use a subclass exposing protected methods for testing
        $tester = new class() extends MinimalModelForHandleErrors {
            public function publicFormatErrorForApi(array $errorData): array
            {
                return $this->formatErrorForApi($errorData);
            }
        };

        MinimalModelForHandleErrors::configureErrorHandling(['format_for_api' => true]);
        $formatted = $tester->publicFormatErrorForApi($error);

        static::assertArrayHasKey('debug', $formatted);
        static::assertArrayHasKey('error', $formatted);
        static::assertArrayHasKey('suggestions', $formatted['error']);
    }

    public function testGetErrorStatsCountsErrorsForModel(): void
    {
        // ensure at least one error exists in handler
        $m = new MinimalModelForHandleErrors();
        $m->safeSave();

        $stats = MinimalModelForHandleErrors::getErrorStats();
        static::assertIsArray($stats);
        static::assertArrayHasKey('total_errors', $stats);
        static::assertGreaterThanOrEqual(1, $stats['total_errors']);
    }
}
