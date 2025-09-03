<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORMException;

/**
 * Test unitario para validar la funcionalidad de validación y Mass Assignment
 * que implementa la Task 1.6.
 */
class ValidationUnitTest extends TestCase
{
    public function test_fillable_attributes_allow_mass_assignment(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);

        static::assertSame('John Doe', $model->name);
        static::assertSame('john@example.com', $model->email);
    }

    public function test_fillable_attributes_block_unallowed_fields(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'email' is not fillable");

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);
    }

    public function test_guarded_attributes_block_mass_assignment(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['id', 'created_at'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'id' is guarded against mass assignment");

        $model->fill(['name' => 'John Doe', 'id' => 1]);
    }

    public function test_wildcard_guard_blocks_all_fields(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['*'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Mass assignment is not allowed');

        $model->fill(['name' => 'John Doe']);
    }

    public function test_custom_validation_rules(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected array $rules = [
                'name' => ['required', 'min:3'],
                'email' => ['required', 'email'],
            ];
        };

        $model->fill(['name' => 'Jo', 'email' => 'invalid-email']);

        $errors = $model->validate();

        static::assertNotEmpty($errors);
        static::assertContains('The name must be at least 3 characters.', $errors);
        static::assertContains('The email must be a valid email address.', $errors);
    }

    public function test_valid_model_passes_validation(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected array $rules = [
                'name' => ['required'],
                'email' => ['required', 'email'],
            ];
        };

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);

        $errors = $model->validate();

        static::assertEmpty($errors);
    }

    public function test_is_fillable_method(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        static::assertTrue($model->isFillable('name'));
        static::assertTrue($model->isFillable('email'));
        static::assertFalse($model->isFillable('id'));
    }

    public function test_is_guarded_method(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        static::assertFalse($model->isGuarded('name'));
        static::assertFalse($model->isGuarded('email'));
        static::assertTrue($model->isGuarded('id'));
    }

    public function test_max_length_validation_rule(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name'];

            protected array $rules = [
                'name' => ['max:10'],
            ];
        };

        $model->fill(['name' => 'This is a very long name that exceeds the limit']);

        $errors = $model->validate();

        static::assertNotEmpty($errors);
        static::assertContains('The name may not be greater than 10 characters.', $errors);
    }

    public function test_numeric_validation_rule(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['age'];

            protected array $rules = [
                'age' => ['numeric'],
            ];
        };

        $model->fill(['age' => 'not-a-number']);

        $errors = $model->validate();

        static::assertNotEmpty($errors);
        static::assertContains('The age must be numeric.', $errors);
    }

    public function test_required_validation_rule(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name'];

            protected array $rules = [
                'name' => ['required'],
            ];
        };

        $model->fill(['name' => '']);

        $errors = $model->validate();

        static::assertNotEmpty($errors);
        static::assertContains('The name field is required.', $errors);
    }

    public function test_min_length_validation_rule(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name'];

            protected array $rules = [
                'name' => ['min:5'],
            ];
        };

        $model->fill(['name' => 'Jo']);

        $errors = $model->validate();

        static::assertNotEmpty($errors);
        static::assertContains('The name must be at least 5 characters.', $errors);
    }

    public function test_get_fillable_method(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        static::assertSame(['name', 'email'], $model->getFillable());
    }

    public function test_get_guarded_method(): void
    {
        $model = new class('test_users', null) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['id', 'created_at'];
        };

        static::assertSame(['id', 'created_at'], $model->getGuarded());
    }
}
