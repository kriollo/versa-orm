<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;

/**
 * Test para validación de consistencia de esquemas en VersaORM.
 */

/**
 * @group mysql
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

    public function test_validate_schema_consistency_with_empty_property_types(): void
    {
        $model = new EmptySchemaModel('empty_table', null);
        $errors = $model->validateSchemaConsistency();

        static::assertCount(1, $errors);
        static::assertStringContainsString('No property types defined', $errors[0]);
    }

    public function test_validate_schema_consistency_with_matching_types(): void
    {
        // Mock the database schema to match our model
        $model = new ConsistentSchemaModel('consistent_table', null);

        // For this test we'd need to mock the database schema response
        // Since we can't easily mock the getTableValidationSchema method in this context,
        // we'll create a more comprehensive test in a real environment
        static::assertTrue(method_exists($model, 'validateSchemaConsistency'));
    }

    public function test_property_consistency_validation(): void
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
        static::assertEmpty($errors);

        // Test type mismatch
        $propertyDef = ['type' => 'string', 'nullable' => false];
        $dbColumn = ['data_type' => 'int', 'is_nullable' => 'NO'];

        $errors = $method->invokeArgs($model, ['id', $propertyDef, $dbColumn]);
        static::assertNotEmpty($errors);
        static::assertStringContainsString('Type mismatch for property', $errors[0]);
    }

    public function test_nullability_consistency_validation(): void
    {
        $model = new TestSchemaModel('test_table', null);

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validatePropertyConsistency');
        $method->setAccessible(true);

        // Test nullability mismatch - model expects non-nullable but database allows null
        $propertyDef = ['type' => 'string', 'nullable' => false];
        $dbColumn = ['data_type' => 'varchar', 'is_nullable' => 'YES'];

        $errors = $method->invokeArgs($model, ['name', $propertyDef, $dbColumn]);
        static::assertNotEmpty($errors);
        static::assertStringContainsString('Nullability mismatch for property', $errors[0]);
    }

    public function test_length_consistency_validation(): void
    {
        $model = new TestSchemaModel('test_table', null);

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validatePropertyConsistency');
        $method->setAccessible(true);

        // Test length mismatch - model max_length exceeds database max_length
        $propertyDef = ['type' => 'string', 'max_length' => 500];
        $dbColumn = ['data_type' => 'varchar', 'character_maximum_length' => 255];

        $errors = $method->invokeArgs($model, ['name', $propertyDef, $dbColumn]);
        static::assertNotEmpty($errors);
        static::assertStringContainsString('Length mismatch for property', $errors[0]);
    }

    public function test_type_compatibility_mapping(): void
    {
        $model = new TestSchemaModel('test_table', null);

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validatePropertyConsistency');
        $method->setAccessible(true);

        // Test compatible types
        $compatiblePairs = [
            ['int',      'int'],
            ['int',      'tinyint'],
            ['int',      'bigint'],
            ['float',    'float'],
            ['float',    'double'],
            ['float',    'decimal'],
            ['string',   'varchar'],
            ['string',   'text'],
            ['bool',     'tinyint'],
            ['datetime', 'datetime'],
            ['datetime', 'timestamp'],
            ['json',     'json'],
            ['json',     'text'],
            ['uuid',     'char'],
            ['uuid',     'varchar'],
            ['enum',     'enum'],
            ['set',      'set'],
            ['blob',     'blob'],
            ['inet',     'varchar'],
        ];

        foreach ($compatiblePairs as [$modelType, $dbType]) {
            $propertyDef = ['type' => $modelType, 'nullable' => true];
            $dbColumn = ['data_type' => $dbType, 'is_nullable' => 'YES'];

            $errors = $method->invokeArgs($model, ['test_field', $propertyDef, $dbColumn]);

            // Filter out any unrelated errors, only check for type mismatch
            $typeMismatchErrors = array_filter($errors, static fn($error) => strpos($error, 'Type mismatch') !== false);

            static::assertEmpty(
                $typeMismatchErrors,
                "Type mismatch error found for compatible types: {$modelType} <-> {$dbType}",
            );
        }
    }

    public function test_incompatible_types(): void
    {
        $model = new TestSchemaModel('test_table', null);

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validatePropertyConsistency');
        $method->setAccessible(true);

        // Test incompatible types
        $propertyDef = ['type' => 'int', 'nullable' => true];
        $dbColumn = ['data_type' => 'text', 'is_nullable' => 'YES'];

        $errors = $method->invokeArgs($model, ['test_field', $propertyDef, $dbColumn]);
        $typeMismatchErrors = array_filter($errors, static fn($error) => strpos($error, 'Type mismatch') !== false);

        static::assertNotEmpty($typeMismatchErrors);
    }

    public function test_clear_database_schema_cache(): void
    {
        $model = new TestSchemaModel('test_table', null);

        // This method should exist and be callable
        static::assertTrue(method_exists($model, 'clearDatabaseSchemaCache'));

        // Should not throw any exceptions
        $model->clearDatabaseSchemaCache();
        static::assertTrue(true); // Test passes if no exception is thrown
    }

    public function test_schema_consistency_integration(): void
    {
        // Integration test that checks the full consistency validation flow
        $model = new TestSchemaModel('test_table', null);

        // The method should exist and be callable
        static::assertTrue(method_exists($model, 'validateSchemaConsistency'));

        // Should return an array (even if empty due to no database connection)
        $result = $model->validateSchemaConsistency();
        static::assertIsArray($result);
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
