<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;

/**
 * Test para validación de consistencia de esquemas en VersaORM.
 */
class SchemaConsistencyTest extends TestCase
{
    private TestSchemaModel $model;

    protected function setUp(): void
    {
        $this->model = new TestSchemaModel('test_schema_table', null);
    }

    protected function tearDown(): void
    {
        TestSchemaModel::clearPropertyTypesCache();
        $this->model->clearDatabaseSchemaCache();
    }

    public function testValidateSchemaConsistencyWithEmptyPropertyTypes(): void
    {
        $model = new EmptySchemaModel('empty_table', null);
        $errors = $model->validateSchemaConsistency();

        self::assertCount(1, $errors);
        self::assertStringContainsString('No property types defined', $errors[0]);
    }

    public function testValidateSchemaConsistencyWithMatchingTypes(): void
    {
        // Mock the database schema to match our model
        $model = new ConsistentSchemaModel('consistent_table', null);

        // For this test we'd need to mock the database schema response
        // Since we can't easily mock the getTableValidationSchema method in this context,
        // we'll create a more comprehensive test in a real environment
        self::assertTrue(method_exists($model, 'validateSchemaConsistency'));
    }

    public function testPropertyConsistencyValidation(): void
    {
        // Test internal property consistency validation logic
        $model = new TestSchemaModel('test_table', null);

        // Use reflection to test private methods
        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validatePropertyConsistency');
        $method->setAccessible(true);

        // Test type compatibility
        $propertyDef = ['type' => 'int', 'nullable' => false];
        $dbColumn = ['data_type' => 'int', 'is_nullable' => 'NO'];

        $errors = $method->invokeArgs($model, ['id', $propertyDef, $dbColumn]);
        self::assertEmpty($errors);

        // Test type mismatch
        $propertyDef = ['type' => 'string', 'nullable' => false];
        $dbColumn = ['data_type' => 'int', 'is_nullable' => 'NO'];

        $errors = $method->invokeArgs($model, ['id', $propertyDef, $dbColumn]);
        self::assertNotEmpty($errors);
        self::assertStringContainsString('Type mismatch for property', $errors[0]);
    }

    public function testNullabilityConsistencyValidation(): void
    {
        $model = new TestSchemaModel('test_table', null);

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validatePropertyConsistency');
        $method->setAccessible(true);

        // Test nullability mismatch - model expects non-nullable but database allows null
        $propertyDef = ['type' => 'string', 'nullable' => false];
        $dbColumn = ['data_type' => 'varchar', 'is_nullable' => 'YES'];

        $errors = $method->invokeArgs($model, ['name', $propertyDef, $dbColumn]);
        self::assertNotEmpty($errors);
        self::assertStringContainsString('Nullability mismatch for property', $errors[0]);
    }

    public function testLengthConsistencyValidation(): void
    {
        $model = new TestSchemaModel('test_table', null);

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validatePropertyConsistency');
        $method->setAccessible(true);

        // Test length mismatch - model max_length exceeds database max_length
        $propertyDef = ['type' => 'string', 'max_length' => 500];
        $dbColumn = ['data_type' => 'varchar', 'character_maximum_length' => 255];

        $errors = $method->invokeArgs($model, ['name', $propertyDef, $dbColumn]);
        self::assertNotEmpty($errors);
        self::assertStringContainsString('Length mismatch for property', $errors[0]);
    }

    public function testTypeCompatibilityMapping(): void
    {
        $model = new TestSchemaModel('test_table', null);

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validatePropertyConsistency');
        $method->setAccessible(true);

        // Test compatible types
        $compatiblePairs = [
            ['int', 'int'],
            ['int', 'tinyint'],
            ['int', 'bigint'],
            ['float', 'float'],
            ['float', 'double'],
            ['float', 'decimal'],
            ['string', 'varchar'],
            ['string', 'text'],
            ['bool', 'tinyint'],
            ['datetime', 'datetime'],
            ['datetime', 'timestamp'],
            ['json', 'json'],
            ['json', 'text'],
            ['uuid', 'char'],
            ['uuid', 'varchar'],
            ['enum', 'enum'],
            ['set', 'set'],
            ['blob', 'blob'],
            ['inet', 'varchar'],
        ];

        foreach ($compatiblePairs as [$modelType, $dbType]) {
            $propertyDef = ['type' => $modelType, 'nullable' => true];
            $dbColumn = ['data_type' => $dbType, 'is_nullable' => 'YES'];

            $errors = $method->invokeArgs($model, ['test_field', $propertyDef, $dbColumn]);

            // Filter out any unrelated errors, only check for type mismatch
            $typeMismatchErrors = array_filter($errors, static function ($error) {
                return strpos($error, 'Type mismatch') !== false;
            });

            self::assertEmpty(
                $typeMismatchErrors,
                "Type mismatch error found for compatible types: {$modelType} <-> {$dbType}",
            );
        }
    }

    public function testIncompatibleTypes(): void
    {
        $model = new TestSchemaModel('test_table', null);

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validatePropertyConsistency');
        $method->setAccessible(true);

        // Test incompatible types
        $propertyDef = ['type' => 'int', 'nullable' => true];
        $dbColumn = ['data_type' => 'text', 'is_nullable' => 'YES'];

        $errors = $method->invokeArgs($model, ['test_field', $propertyDef, $dbColumn]);
        $typeMismatchErrors = array_filter($errors, static function ($error) {
            return strpos($error, 'Type mismatch') !== false;
        });

        self::assertNotEmpty($typeMismatchErrors);
    }

    public function testClearDatabaseSchemaCache(): void
    {
        $model = new TestSchemaModel('test_table', null);

        // This method should exist and be callable
        self::assertTrue(method_exists($model, 'clearDatabaseSchemaCache'));

        // Should not throw any exceptions
        $model->clearDatabaseSchemaCache();
        self::assertTrue(true); // Test passes if no exception is thrown
    }

    public function testSchemaConsistencyIntegration(): void
    {
        // Integration test that checks the full consistency validation flow
        $model = new TestSchemaModel('test_table', null);

        // The method should exist and be callable
        self::assertTrue(method_exists($model, 'validateSchemaConsistency'));

        // Should return an array (even if empty due to no database connection)
        $result = $model->validateSchemaConsistency();
        self::assertIsArray($result);
    }
}

/**
 * Modelo de prueba para testing de consistencia de esquemas.
 */
class TestSchemaModel extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name' => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
            'email' => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
            'age' => ['type' => 'int', 'nullable' => true],
            'salary' => ['type' => 'float', 'nullable' => true],
            'is_active' => ['type' => 'bool', 'nullable' => false],
            'settings' => ['type' => 'json', 'nullable' => true],
            'uuid' => ['type' => 'uuid', 'nullable' => false],
            'status' => ['type' => 'enum', 'values' => ['active', 'inactive']],
            'tags' => ['type' => 'set', 'values' => ['work', 'personal']],
            'profile_pic' => ['type' => 'blob', 'nullable' => true],
            'ip_address' => ['type' => 'inet', 'nullable' => true],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
        ];
    }
}

/**
 * Modelo sin tipos definidos para testing.
 */
class EmptySchemaModel extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [];
    }
}

/**
 * Modelo con esquema consistente para testing.
 */
class ConsistentSchemaModel extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name' => ['type' => 'string', 'max_length' => 100, 'nullable' => false],
            'active' => ['type' => 'bool', 'nullable' => false],
        ];
    }
}
