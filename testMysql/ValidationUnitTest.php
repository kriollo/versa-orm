<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORMException;

/**
 * Test unitario para validar la funcionalidad de validación y Mass Assignment
 * que implementa la Task 1.6.
 */
/**
 * @group mysql
 */
class ValidationUnitTest extends TestCase
{
    public function testFillableAttributesAllowMassAssignment(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);

        self::assertSame('John Doe', $model->name);
        self::assertSame('john@example.com', $model->email);
    }

    public function testFillableAttributesBlockUnallowedFields(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = ['name'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'email' is not fillable");

        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);
    }

    public function testGuardedAttributesBlockMassAssignment(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['id', 'created_at'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'id' is guarded against mass assignment");

        $model->fill(['name' => 'John Doe', 'id' => 1]);
    }

    public function testWildcardGuardBlocksAllFields(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['*'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Mass assignment is not allowed');

        $model->fill(['name' => 'John Doe']);
    }

    public function testCustomValidationRules(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
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

    public function testValidModelPassesValidation(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
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

    public function testIsFillableMethod(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        self::assertTrue($model->isFillable('name'));
        self::assertTrue($model->isFillable('email'));
        self::assertFalse($model->isFillable('id'));
    }

    public function testIsGuardedMethod(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        self::assertFalse($model->isGuarded('name'));
        self::assertFalse($model->isGuarded('email'));
        self::assertTrue($model->isGuarded('id'));
    }

    public function testMaxLengthValidationRule(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
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

    public function testNumericValidationRule(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
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

    public function testRequiredValidationRule(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = ['name'];

            protected array $rules = [
                'name' => ['required'],
            ];
        };

        $model->fill(['name' => '']);

        $errors = $model->validate();

        self::assertNotEmpty($errors);
        self::assertContains('The name field is required.', $errors);
    }

    public function testMinLengthValidationRule(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = ['name'];

            protected array $rules = [
                'name' => ['min:5'],
            ];
        };

        $model->fill(['name' => 'Jo']);

        $errors = $model->validate();

        self::assertNotEmpty($errors);
        self::assertContains('The name must be at least 5 characters.', $errors);
    }

    public function testGetFillableMethod(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        self::assertSame(['name', 'email'], $model->getFillable());
    }

    public function testGetGuardedMethod(): void
    {
        $model = new class ('test_users', null) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['id', 'created_at'];
        };

        self::assertSame(['id', 'created_at'], $model->getGuarded());
    }
}
