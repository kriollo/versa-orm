<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;
use VersaORM\VersaORMException;

require_once __DIR__ . '/TestCase.php';

class AdvancedTypeMappingTest extends TestCase
{
    public function testJsonTypeConversion(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $jsonString  = '{"key": "value"}';
        $fieldSchema = ['type' => 'json'];

        $result = $model->convertValueByTypeMapping('json_field', $jsonString, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['key' => 'value'], $result);
    }

    public function testJsonTypeConversionWithAlreadyDecodedData(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $arrayData   = ['key' => 'value'];
        $fieldSchema = ['type' => 'json'];

        $result = $model->convertValueByTypeMapping('json_field', $arrayData, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['key' => 'value'], $result);
    }

    public function testUuidTypeConversion(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $uuid        = '550e8400-e29b-41d4-a716-446655440000';
        $fieldSchema = ['type' => 'uuid'];

        $result = $model->convertValueByTypeMapping('uuid_field', $uuid, $fieldSchema);

        self::assertIsString($result);
        self::assertSame($uuid, $result);
    }

    public function testArrayTypeConversionFromJsonString(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $arrayData   = '["value1", "value2"]';
        $fieldSchema = ['type' => 'array'];

        $result = $model->convertValueByTypeMapping('array_field', $arrayData, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['value1', 'value2'], $result);
    }

    public function testArrayTypeConversionFromArray(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $arrayData   = ['value1', 'value2'];
        $fieldSchema = ['type' => 'array'];

        $result = $model->convertValueByTypeMapping('array_field', $arrayData, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['value1', 'value2'], $result);
    }

    public function testArrayTypeConversionFromScalarValue(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $scalarValue = 'single_value';
        $fieldSchema = ['type' => 'array'];

        $result = $model->convertValueByTypeMapping('array_field', $scalarValue, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['single_value'], $result);
    }

    public function testSetTypeConversionFromCommaSeparated(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $setValue    = 'option1,option2,option3';
        $fieldSchema = ['type' => 'set'];

        $result = $model->convertValueByTypeMapping('set_field', $setValue, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['option1', 'option2', 'option3'], $result);
    }

    public function testEnumTypeConversionFromCommaSeparated(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $enumValue   = 'active,pending';
        $fieldSchema = ['type' => 'enum'];

        $result = $model->convertValueByTypeMapping('enum_field', $enumValue, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['active', 'pending'], $result);
    }

    public function testUnknownTypeReturnsOriginalValue(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $value       = 'some_value';
        $fieldSchema = ['type' => 'unknown_type'];

        $result = $model->convertValueByTypeMapping('unknown_field', $value, $fieldSchema);

        self::assertSame('some_value', $result);
    }

    public function testTypeMappingThrowsExceptionWhenTypeNotDefined(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Type mapping not defined for field: test_field');

        $model       = new VersaModel('test_table', self::$orm);
        $value       = 'some_value';
        $fieldSchema = []; // No type defined

        $model->convertValueByTypeMapping('test_field', $value, $fieldSchema);
    }

    public function testComplexJsonConversion(): void
    {
        $model       = new VersaModel('test_table', self::$orm);
        $complexJson = '{"users": [{"name": "John", "age": 30}, {"name": "Jane", "age": 25}], "total": 2}';
        $fieldSchema = ['type' => 'json'];

        $result = $model->convertValueByTypeMapping('data_field', $complexJson, $fieldSchema);

        $expected = [
            'users' => [
                ['name' => 'John', 'age' => 30],
                ['name' => 'Jane', 'age' => 25],
            ],
            'total' => 2,
        ];

        self::assertIsArray($result);
        self::assertSame($expected, $result);
    }

    public function testLoadTypeMappingConfig(): void
    {
        $configPath = __DIR__ . '/type_mapping_config.json';
        $config     = VersaModel::loadTypeMappingConfig($configPath);

        self::assertIsArray($config);
        self::assertArrayHasKey('json_field', $config);
        self::assertArrayHasKey('uuid_field', $config);
        self::assertArrayHasKey('array_field', $config);
        self::assertSame('json', $config['json_field']['type']);
        self::assertSame('uuid', $config['uuid_field']['type']);
        self::assertSame('array', $config['array_field']['type']);
    }

    public function testLoadTypeMappingConfigFileNotFound(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Type mapping configuration file not found:');

        VersaModel::loadTypeMappingConfig('/nonexistent/path.json');
    }

    public function testLoadTypeMappingConfigInvalidJson(): void
    {
        $invalidJsonPath = sys_get_temp_dir() . '/invalid_type_mapping.json';
        file_put_contents($invalidJsonPath, '{invalid json}');

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid JSON in type mapping configuration:');

        try {
            VersaModel::loadTypeMappingConfig($invalidJsonPath);
        } finally {
            unlink($invalidJsonPath);
        }
    }
}
