<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;
use VersaORM\VersaORMException;

/**
 * Test para validar la funcionalidad de validación y Mass Assignment
 * que implementa la Task 1.6.
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

    public function testFillableAttributesAllowMassAssignment(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);

        $this->assertEquals('John Doe', $model->name);
        $this->assertEquals('john@example.com', $model->email);
    }

    public function testFillableAttributesBlockUnallowedFields(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'email' is not fillable");

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);
    }

    public function testGuardedAttributesBlockMassAssignment(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = [];
            protected array $guarded  = ['id', 'created_at'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'id' is guarded against mass assignment");

        $model->fill(['name' => 'John Doe', 'id' => 1]);
    }

    public function testWildcardGuardBlocksAllFields(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = [];
            protected array $guarded  = ['*'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Mass assignment is not allowed');

        $model->fill(['name' => 'John Doe']);
    }

    public function testCustomValidationRules(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
            protected array $rules    = [
                'name'  => ['required', 'min:3'],
                'email' => ['required', 'email'],
            ];
        };

        $model->fill(['name' => 'Jo', 'email' => 'invalid-email']);

        $errors = $model->validate();

        $this->assertNotEmpty($errors);
        $this->assertContains('The name must be at least 3 characters.', $errors);
        $this->assertContains('The email must be a valid email address.', $errors);
    }

    public function testValidModelPassesValidation(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
            protected array $rules    = [
                'name'  => ['required'],
                'email' => ['required', 'email'],
            ];
        };

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);

        $errors = $model->validate();

        $this->assertEmpty($errors);
    }

    public function testStoreWithValidationFailureThrowsException(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
            protected array $rules    = [
                'name'  => ['required'],
                'email' => ['required', 'email'],
            ];
        };

        $model->fill(['name' => '', 'email' => 'invalid-email']);

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Validation failed');

        $model->store();
    }

    public function testIsFillableMethod(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $this->assertTrue($model->isFillable('name'));
        $this->assertTrue($model->isFillable('email'));
        $this->assertFalse($model->isFillable('id'));
    }

    public function testIsGuardedMethod(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $this->assertFalse($model->isGuarded('name'));
        $this->assertFalse($model->isGuarded('email'));
        $this->assertTrue($model->isGuarded('id'));
    }

    public function testUpdateMethodWithMassAssignment(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);
        $model->store();

        // Actualizar con mass assignment
        $model->update(['name' => 'Jane Doe']);

        $this->assertEquals('Jane Doe', $model->name);
        $this->assertEquals('john@example.com', $model->email); // Email no cambia
    }

    public function testCreateStaticMethodWithValidation(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];
            protected array $rules    = [
                'name'  => ['required'],
                'email' => ['required', 'email'],
            ];
        };

        $instance = $model::create(['name' => 'John Doe', 'email' => 'john@example.com']);

        $this->assertEquals('John Doe', $instance->name);
        $this->assertEquals('john@example.com', $instance->email);
    }

    public function testMaxLengthValidationRule(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['name'];
            protected array $rules    = [
                'name' => ['max:10'],
            ];
        };

        $model->fill(['name' => 'This is a very long name that exceeds the limit']);

        $errors = $model->validate();

        $this->assertNotEmpty($errors);
        $this->assertContains('The name may not be greater than 10 characters.', $errors);
    }

    public function testNumericValidationRule(): void
    {
        $model = new class ('test_users', self::$orm) extends VersaModel {
            protected array $fillable = ['age'];
            protected array $rules    = [
                'age' => ['numeric'],
            ];
        };

        $model->fill(['age' => 'not-a-number']);

        $errors = $model->validate();

        $this->assertNotEmpty($errors);
        $this->assertContains('The age must be numeric.', $errors);
    }
}
