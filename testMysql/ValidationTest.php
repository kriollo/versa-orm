<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;
use VersaORM\VersaORMException;

/**
 * Test para validar la funcionalidad de validación y Mass Assignment
 * que implementa la Task 1.6.
 */
/**
 * @group mysql
 */
class ValidationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Crear tabla de prueba para ValidationTest
        self::$orm->exec('CREATE TABLE IF NOT EXISTS test_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            age INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB');
    }

    public function test_fillable_attributes_allow_mass_assignment(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);

        self::assertSame('John Doe', $model->name);
        self::assertSame('john@example.com', $model->email);
    }

    public function test_fillable_attributes_block_unallowed_fields(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'email' is not fillable");

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);
    }

    public function test_guarded_attributes_block_mass_assignment(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['id', 'created_at'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'id' is guarded against mass assignment");

        $model->fill(['name' => 'John Doe', 'id' => 1]);
    }

    public function test_wildcard_guard_blocks_all_fields(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['*'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Mass assignment is not allowed');

        $model->fill(['name' => 'John Doe']);
    }

    public function test_custom_validation_rules(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected array $rules = [
                'name' => ['required', 'min:3'],
                'email' => ['required', 'email'],
            ];
        };

        $model->fill(['name' => 'Jo', 'email' => 'invalid-email']);

        $errors = $model->validate();

        self::assertNotEmpty($errors);
        self::assertContains('The name must be at least 3 characters.', $errors);
        self::assertContains('The email must be a valid email address.', $errors);
    }

    public function test_valid_model_passes_validation(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected array $rules = [
                'name' => ['required'],
                'email' => ['required', 'email'],
            ];
        };

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);

        $errors = $model->validate();

        self::assertEmpty($errors);
    }

    public function test_store_with_validation_failure_throws_exception(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected array $rules = [
                'name' => ['required'],
                'email' => ['required', 'email'],
            ];
        };

        $model->fill(['name' => '', 'email' => 'invalid-email']);

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Validation failed');

        $model->store();
    }

    public function test_is_fillable_method(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        self::assertTrue($model->isFillable('name'));
        self::assertTrue($model->isFillable('email'));
        self::assertFalse($model->isFillable('id'));
    }

    public function test_is_guarded_method(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        self::assertFalse($model->isGuarded('name'));
        self::assertFalse($model->isGuarded('email'));
        self::assertTrue($model->isGuarded('id'));
    }

    public function test_update_method_with_mass_assignment(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);
        $model->store();

        // Actualizar con mass assignment
        $model->update(['name' => 'Jane Doe']);

        self::assertSame('Jane Doe', $model->name);
        self::assertSame('john@example.com', $model->email); // Email no cambia
    }

    public function test_create_static_method_with_validation(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected array $rules = [
                'name' => ['required'],
                'email' => ['required', 'email'],
            ];
        };

        $instance = $model::create(['name' => 'John Doe', 'email' => 'john@example.com']);

        self::assertSame('John Doe', $instance->name);
        self::assertSame('john@example.com', $instance->email);
    }

    public function test_max_length_validation_rule(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name'];

            protected array $rules = [
                'name' => ['max:10'],
            ];
        };

        $model->fill(['name' => 'This is a very long name that exceeds the limit']);

        $errors = $model->validate();

        self::assertNotEmpty($errors);
        self::assertContains('The name may not be greater than 10 characters.', $errors);
    }

    public function test_numeric_validation_rule(): void
    {
        $model = new class('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['age'];

            protected array $rules = [
                'age' => ['numeric'],
            ];
        };

        $model->fill(['age' => 'not-a-number']);

        $errors = $model->validate();

        self::assertNotEmpty($errors);
        self::assertContains('The age must be numeric.', $errors);
    }
}
