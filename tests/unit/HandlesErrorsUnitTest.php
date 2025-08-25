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

        $this->assertNull($result, 'safeSave should return null when throw_on_error is false');
        $this->assertTrue($m->hasError(), 'Model should have lastError set');
        $this->assertSame('Simulated save error', $m->getLastErrorMessage());
    }

    public function testFormatErrorForApiIncludesDebugWhenDebugMode(): void
    {
        ErrorHandler::setDebugMode(true);

        $m = new MinimalModelForHandleErrors();

        // trigger error
        $m->safeSave();

        $error = $m->getLastError();
        $this->assertIsArray($error);

        // format for api should include debug block when debug mode is on
        // use a subclass exposing protected methods for testing
        $tester = new class () extends MinimalModelForHandleErrors {
            public function publicFormatErrorForApi(array $errorData): array
            {
                return $this->formatErrorForApi($errorData);
            }
        };

        MinimalModelForHandleErrors::configureErrorHandling(['format_for_api' => true]);
        $formatted = $tester->publicFormatErrorForApi($error);

        $this->assertArrayHasKey('debug', $formatted);
        $this->assertArrayHasKey('error', $formatted);
        $this->assertArrayHasKey('suggestions', $formatted['error']);
    }

    public function testGetErrorStatsCountsErrorsForModel(): void
    {
        // ensure at least one error exists in handler
        $m = new MinimalModelForHandleErrors();
        $m->safeSave();

        $stats = MinimalModelForHandleErrors::getErrorStats();
        $this->assertIsArray($stats);
        $this->assertArrayHasKey('total_errors', $stats);
        $this->assertGreaterThanOrEqual(1, $stats['total_errors']);
    }
}
