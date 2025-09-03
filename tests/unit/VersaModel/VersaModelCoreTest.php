<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

/**
 * @group sqlite
 */
final class VersaModelCoreTest extends TestCase
{
    public function testFillableAllowsDefinedFieldAndBlocksWhenGuardedStar(): void
    {
        $model = new class('users', null) extends VersaModel {
            protected array $fillable = ['name'];
        };

        $model->fill(['name' => 'Alice']);
        static::assertSame('Alice', $model->getAttribute('name'));

        $blocked = new class('users', null) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['*'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Mass assignment is not allowed');
        $blocked->fill(['email' => 'a@b.com']);
    }

    public function testFillableThrowsForSpecificGuardedField(): void
    {
        $m = new class('users', null) extends VersaModel {
            protected array $fillable = [];

            protected array $guarded = ['email'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'email' is guarded");
        $m->fill(['email' => 'x']);
    }

    public function testPrepareValueForDatabaseSimpleHandlesBooleansDateAndArray(): void
    {
        $model = new class('users', null) extends VersaModel {};

        $ref = new ReflectionObject($model);
        $method = $ref->getMethod('prepareValueForDatabaseSimple');
        $method->setAccessible(true);

        static::assertSame(1, $method->invoke($model, true));
        static::assertSame(0, $method->invoke($model, false));

        $dt = new DateTime('2020-01-02 15:04:05');
        static::assertStringContainsString('2020-01-02', (string) $method->invoke($model, $dt));

        $arr = ['a' => 1];
        $json = $method->invoke($model, $arr);
        static::assertIsString($json);
        static::assertStringContainsString('"a"', $json);
    }

    public function testValidateFieldAgainstSchemaIntegerAndEmail(): void
    {
        $model = new class('users', null) extends VersaModel {};

        $ref = new ReflectionObject($model);
        $method = $ref->getMethod('validateFieldAgainstSchema');
        $method->setAccessible(true);

        // Integer expected but given non-numeric
        $schemaInt = ['data_type' => 'int'];
        $errors = $method->invoke($model, 'age', 'abc', $schemaInt);
        static::assertStringContainsString('must be an integer', $errors[0]);

        // Email validation rule
        $schemaEmail = ['data_type' => 'varchar', 'validation_rules' => ['email']];
        $errors2 = $method->invoke($model, 'contact', 'not-an-email', $schemaEmail);
        static::assertStringContainsString('must be a valid email', $errors2[0]);
    }

    public function testStoreThrowsOnValidation(): void
    {
        $vFail = new class('users', null) extends VersaModel {
            public function validate(): array
            {
                return ['some error'];
            }
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Validation failed');
        $vFail->store();
    }

    public function testStoreThrowsWhenNoOrm(): void
    {
        $noOrm = new class('users', null) extends VersaModel {
            public function validate(): array
            {
                return [];
            }
        };

        // Ensure global ORM cleared
        VersaModel::setORM(null);

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('No ORM instance available for store operation');
        $noOrm->store();
    }

    public function testStoreThrowsNoDataToInsert(): void
    {
        // Provide a real VersaORM instance for this test
        $realOrm = new VersaORM([]);
        VersaModel::setORM($realOrm);

        $mNoData = new class('users', null) extends VersaModel {
            // attributes default empty -> preparedAttributes will be empty
            public function validate(): array
            {
                return [];
            }
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('No data to insert');
        $mNoData->store();
    }
}
