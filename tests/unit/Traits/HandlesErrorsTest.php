<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Traits;

use PHPUnit\Framework\TestCase;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaORMException;

/**
 * @group core
 */
class HandlesErrorsTest extends TestCase
{
    private $model;

    protected function setUp(): void
    {
        $this->model = new class() {
            use HandlesErrors;

            public $attributes = ['id' => 1];

            public function save()
            {
                return true;
            }

            public function delete()
            {
                throw new VersaORMException('Delete failed', 'DELETE_ERROR');
            }

            public function getTable()
            {
                return 'test_table';
            }
        };

        // Reset error config for isolation
        $this->model::configureErrorHandling([
            'log_errors' => false,
            'throw_on_error' => false,
            'format_for_api' => false,
        ]);
    }

    public function testSafeSaveSuccess(): void
    {
        $result = $this->model->safeSave();
        static::assertTrue($result);
        static::assertFalse($this->model->hasError());
    }

    public function testSafeDeleteFailureHandlesException(): void
    {
        $result = $this->model->safeDelete();

        static::assertNull($result);
        static::assertTrue($this->model->hasError());
        static::assertSame('Delete failed', $this->model->getLastErrorMessage());
        static::assertSame('DELETE_ERROR', $this->model->getLastErrorCode());
    }

    public function testConfigureErrorHandling(): void
    {
        $this->model::configureErrorHandling(['throw_on_error' => true]);

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Delete failed');

        $this->model->safeDelete();
    }

    public function testApiFormatError(): void
    {
        $this->model::configureErrorHandling([
            'throw_on_error' => false,
            'format_for_api' => true,
        ]);

        $result = $this->model->safeDelete();

        static::assertIsArray($result);
        static::assertFalse($result['success']);
        static::assertSame('Delete failed', $result['error']['message']);
        static::assertSame('database_error', $result['error']['type']);
    }
}
