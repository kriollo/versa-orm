<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\ErrorHandler;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaORMException;

require_once __DIR__ . '/TestCase.php';

/**
 * @group mysql
 */
class HandlesErrorsTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();
        // limpiar log de errores antes de cada test
        ErrorHandler::clearErrorLog();
        ErrorHandler::setDebugMode(false);
    }

    public function test_safeSave_returns_formatted_error_when_configured(): void
    {
        // Configurar para no lanzar y formatear para API
        DummyModel::configureErrorHandling([
            'throw_on_error' => false,
            'format_for_api' => true,
            'include_suggestions' => true,
        ]);

        $m = new DummyModel();
        $res = $m->safeSave();

        static::assertIsArray($res);
        static::assertArrayHasKey('error', $res);
        static::assertArrayHasKey('code', $res['error']);
    }

    public function test_getErrorStats_records_error(): void
    {
        DummyModel::configureErrorHandling(['throw_on_error' => false]);
        $m = new DummyModel();
        // trigger an error via safeSave
        $m->safeSave();

        $stats = DummyModel::getErrorStats();
        static::assertIsArray($stats);
        static::assertArrayHasKey('total_errors', $stats);
        static::assertGreaterThanOrEqual(1, $stats['total_errors']);
    }

    public function test_validateBeforeOperation_empty_attributes_sets_error_and_returns_false(): void
    {
        // force config to not throw so we can inspect lastError
        DummyModel::configureErrorHandling(['throw_on_error' => false]);
        $m = new DummyModel();

        $ok = $m->publicValidate('save');
        static::assertFalse($ok);
        static::assertTrue($m->hasError());
        static::assertNotNull($m->getLastErrorMessage());
    }
}

// DummyModel used only for these tests; intentionally minimal to avoid DB interactions
class DummyModel
{
    use HandlesErrors;

    public array $attributes = [];

    public function getTable(): ?string
    {
        return 'dummy';
    }

    // Methods that would normally touch DB, here they throw to exercise error handling
    public function save()
    {
        throw new VersaORMException('simulated save failure', 'VALIDATION_ERROR');
    }

    public function store()
    {
        // no-op for tests
        return null;
    }

    public function update(array $data)
    {
        throw new VersaORMException('simulated update failure', 'UPDATE_ERROR');
    }

    public function delete()
    {
        throw new VersaORMException('simulated delete failure', 'DELETE_ERROR');
    }

    public function upsert(array $uniqueKeys, array $updateColumns = [])
    {
        throw new VersaORMException('simulated upsert failure', 'UPSERT_ERROR');
    }

    public static function find(mixed $id)
    {
        return null;
    }

    // expose protected validateBeforeOperation for testing
    public function publicValidate(string $op): bool
    {
        return $this->validateBeforeOperation($op);
    }
}
