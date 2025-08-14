<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use ReflectionClass;
use VersaORM\VersaModel;

/**
 * Replica simplificada de tests de consistencia de esquema (driver agnóstico).
 */
class SchemaConsistencyTest extends TestCase
{
    protected function tearDown(): void
    {
        TestSchemaModel::clearPropertyTypesCache();
    }

    public function testValidateSchemaConsistencyWithEmptyPropertyTypes(): void
    {
        $model = new EmptySchemaModel('empty_table', null);
        $errors = $model->validateSchemaConsistency();
        self::assertCount(1, $errors);
    }

    public function testPropertyConsistencyValidationTypeMismatch(): void
    {
        $model = new TestSchemaModel('test_table', null);
        $ref = new ReflectionClass($model);
        $m = $ref->getMethod('validatePropertyConsistency');
        $m->setAccessible(true);
        $propertyDef = ['type' => 'string', 'nullable' => false];
        $dbColumn = ['data_type' => 'int', 'is_nullable' => 'NO'];
        $errors = $m->invokeArgs($model, ['id', $propertyDef, $dbColumn]);
        self::assertNotEmpty($errors);
    }
}

class TestSchemaModel extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name' => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
        ];
    }
}

class EmptySchemaModel extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [];
    }
}
