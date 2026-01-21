<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Traits;

use PHPUnit\Framework\TestCase;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaORMException;

/**
 * Tests completos para HandlesErrors trait
 *
 * @group core
 * @group traits
 */
class HandlesErrorsTest extends TestCase
{
    private $model;

    protected function setUp(): void
    {
        $this->model = new class() {
            use HandlesErrors;

            public $attributes = ['id' => 1, 'name' => 'Test'];

            public function save()
            {
                return true;
            }

            public function store()
            {
                return 123; // ID del registro insertado
            }

            public function update(array $data)
            {
                $this->attributes = array_merge($this->attributes, $data);
                return true;
            }

            public function delete()
            {
                throw new VersaORMException('Delete failed', 'DELETE_ERROR');
            }

            public function upsert(array $uniqueKeys, array $updateColumns = [])
            {
                return true;
            }

            public function getTable()
            {
                return 'test_table';
            }

            public static function find($id)
            {
                if ($id === 999) {
                    throw new VersaORMException('Record not found', 'NOT_FOUND');
                }
                if ($id === 1) {
                    $obj = new self();
                    $obj->attributes = ['id' => 1, 'name' => 'Test'];
                    return $obj;
                }
                return null;
            }

            public static function queryTable()
            {
                return new class() {
                    private $conditions = [];

                    public function where($col, $op, $val)
                    {
                        $this->conditions[] = [$col, $op, $val];
                        return $this;
                    }

                    public function findAll()
                    {
                        return [['id' => 1], ['id' => 2]];
                    }
                };
            }

            public function exists(): bool
            {
                return isset($this->attributes['id']);
            }
        };

        // Reset error config for isolation
        $this->model::configureErrorHandling([
            'log_errors' => false,
            'throw_on_error' => false,
            'format_for_api' => false,
            'include_suggestions' => true,
        ]);
    }

    // ====== Tests de configuración ======

    public function test_configure_error_handling(): void
    {
        $this->model::configureErrorHandling([
            'log_errors' => true,
            'throw_on_error' => true,
        ]);

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Delete failed');

        $this->model->safeDelete();
    }

    public function test_configure_error_handling_with_api_format(): void
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

    // ====== Tests de métodos seguros ======

    public function test_safe_save_success(): void
    {
        $result = $this->model->safeSave();
        static::assertTrue($result);
        static::assertFalse($this->model->hasError());
    }

    public function test_safe_store_success(): void
    {
        $result = $this->model->safeStore();
        static::assertSame(123, $result);
        static::assertFalse($this->model->hasError());
    }

    public function test_safe_update_success(): void
    {
        $result = $this->model->safeUpdate(['name' => 'Updated']);
        static::assertTrue($result);
        static::assertFalse($this->model->hasError());
    }

    public function test_safe_delete_failure_handles_exception(): void
    {
        $result = $this->model->safeDelete();

        static::assertNull($result);
        static::assertTrue($this->model->hasError());
        static::assertSame('Delete failed', $this->model->getLastErrorMessage());
        static::assertSame('DELETE_ERROR', $this->model->getLastErrorCode());
    }

    public function test_safe_upsert_success(): void
    {
        $result = $this->model->safeUpsert(['email'], ['name', 'updated_at']);
        static::assertTrue($result);
        static::assertFalse($this->model->hasError());
    }

    // ====== Tests de métodos estáticos ======

    public function test_safe_find_success(): void
    {
        $result = $this->model::safeFind(1);
        static::assertNotNull($result);
    }

    public function test_safe_find_failure(): void
    {
        $result = $this->model::safeFind(999);
        static::assertNull($result);
    }

    public function test_safe_find_all_success(): void
    {
        $result = $this->model::safeFindAll(['status' => 'active']);
        static::assertIsArray($result);
        static::assertCount(2, $result);
    }

    // ====== Tests de getters de error ======

    public function test_get_last_error(): void
    {
        $this->model->safeDelete();
        $error = $this->model->getLastError();

        static::assertIsArray($error);
        static::assertArrayHasKey('error', $error);
        static::assertArrayHasKey('message', $error['error']);
    }

    public function test_has_error(): void
    {
        static::assertFalse($this->model->hasError());

        $this->model->safeDelete();

        static::assertTrue($this->model->hasError());
    }

    public function test_get_last_error_message(): void
    {
        $this->model->safeDelete();
        static::assertSame('Delete failed', $this->model->getLastErrorMessage());
    }

    public function test_get_last_error_code(): void
    {
        $this->model->safeDelete();
        static::assertSame('DELETE_ERROR', $this->model->getLastErrorCode());
    }

    public function test_get_last_error_suggestions(): void
    {
        $this->model->safeDelete();
        $suggestions = $this->model->getLastErrorSuggestions();
        static::assertIsArray($suggestions);
    }

    // ====== Tests de formato de respuesta ======

    public function test_api_format_error(): void
    {
        $this->model::configureErrorHandling([
            'throw_on_error' => false,
            'format_for_api' => true,
        ]);

        $result = $this->model->safeDelete();

        static::assertIsArray($result);
        static::assertFalse($result['success']);
        static::assertSame('Delete failed', $result['error']['message']);
        static::assertSame('DELETE_ERROR', $result['error']['code']);
        static::assertSame('database_error', $result['error']['type']);
    }

    public function test_api_format_includes_suggestions(): void
    {
        $this->model::configureErrorHandling([
            'throw_on_error' => false,
            'format_for_api' => true,
            'include_suggestions' => true,
        ]);

        $result = $this->model->safeDelete();

        static::assertArrayHasKey('suggestions', $result['error']);
    }

    // ====== Tests de validación ======

    public function test_exists_returns_true_when_id_present(): void
    {
        static::assertTrue($this->model->exists());
    }

    public function test_exists_returns_false_when_no_id(): void
    {
        $this->model->attributes = [];
        static::assertFalse($this->model->exists());
    }

    // ====== Tests de casos edge ======

    public function test_multiple_errors_track_last_error_only(): void
    {
        $this->model->safeDelete();
        $firstError = $this->model->getLastErrorMessage();

        // Intentar otra operación con error
        $this->model->safeDelete();
        $secondError = $this->model->getLastErrorMessage();

        // El último error sobrescribe al anterior
        static::assertSame($firstError, $secondError);
        static::assertSame('Delete failed', $secondError);
    }

    public function test_successful_operation_clears_last_error(): void
    {
        // Primero generar un error
        $this->model->safeDelete();
        static::assertTrue($this->model->hasError());

        // Luego ejecutar operación exitosa
        $this->model->safeSave();

        // El último error debería limpiarse si safeSave tiene éxito
        // (esto depende de la implementación del trait)
        static::assertFalse($this->model->hasError());
    }

    public function test_safe_find_all_with_empty_conditions(): void
    {
        $result = $this->model::safeFindAll([]);
        static::assertIsArray($result);
    }

    public function test_safe_find_all_filters_invalid_conditions(): void
    {
        $result = $this->model::safeFindAll([
            'valid' => 'value',
            '' => 'ignored',
            0 => 'ignored',
        ]);
        static::assertIsArray($result);
    }
}
