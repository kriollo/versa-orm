<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;
use VersaORM\VersaORMException;

require_once __DIR__ . '/TestCase.php';

class AdvancedTypeMappingTest extends TestCase
{
    public function test_json_type_conversion(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $jsonString = '{"key": "value"}';
        $fieldSchema = ['type' => 'json'];

        $result = $model->convertValueByTypeMapping('json_field', $jsonString, $fieldSchema);

        static::assertIsArray($result);
        static::assertSame(['key' => 'value'], $result);
    }

    public function test_json_type_conversion_with_already_decoded_data(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $arrayData = ['key' => 'value'];
        $fieldSchema = ['type' => 'json'];

        $result = $model->convertValueByTypeMapping('json_field', $arrayData, $fieldSchema);

        static::assertIsArray($result);
        static::assertSame(['key' => 'value'], $result);
    }

    public function test_uuid_type_conversion(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        $fieldSchema = ['type' => 'uuid'];

        $result = $model->convertValueByTypeMapping('uuid_field', $uuid, $fieldSchema);

        static::assertIsString($result);
        static::assertSame($uuid, $result);
    }

    public function test_array_type_conversion_from_json_string(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $arrayData = '["value1", "value2"]';
        $fieldSchema = ['type' => 'array'];

        $result = $model->convertValueByTypeMapping('array_field', $arrayData, $fieldSchema);

        static::assertIsArray($result);
        static::assertSame(['value1', 'value2'], $result);
    }

    public function test_array_type_conversion_from_array(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $arrayData = ['value1', 'value2'];
        $fieldSchema = ['type' => 'array'];

        $result = $model->convertValueByTypeMapping('array_field', $arrayData, $fieldSchema);

        static::assertIsArray($result);
        static::assertSame(['value1', 'value2'], $result);
    }

    public function test_array_type_conversion_from_scalar_value(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $scalarValue = 'single_value';
        $fieldSchema = ['type' => 'array'];

        $result = $model->convertValueByTypeMapping('array_field', $scalarValue, $fieldSchema);

        static::assertIsArray($result);
        static::assertSame(['single_value'], $result);
    }

    public function test_set_type_conversion_from_comma_separated(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $setValue = 'option1,option2,option3';
        $fieldSchema = ['type' => 'set'];

        $result = $model->convertValueByTypeMapping('set_field', $setValue, $fieldSchema);

        static::assertIsArray($result);
        static::assertSame(['option1', 'option2', 'option3'], $result);
    }

    public function test_enum_type_conversion_from_comma_separated(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $enumValue = 'active,pending';
        $fieldSchema = ['type' => 'enum'];

        $result = $model->convertValueByTypeMapping('enum_field', $enumValue, $fieldSchema);

        static::assertIsArray($result);
        static::assertSame(['active', 'pending'], $result);
    }

    public function test_unknown_type_returns_original_value(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $value = 'some_value';
        $fieldSchema = ['type' => 'unknown_type'];

        $result = $model->convertValueByTypeMapping('unknown_field', $value, $fieldSchema);

        static::assertSame('some_value', $result);
    }

    public function test_type_mapping_throws_exception_when_type_not_defined(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Type mapping not defined for field: test_field');

        $model = new VersaModel('test_table', self::$orm);
        $value = 'some_value';
        $fieldSchema = []; // No type defined

        $model->convertValueByTypeMapping('test_field', $value, $fieldSchema);
    }

    public function test_complex_json_conversion(): void
    {
        $model = new VersaModel('test_table', self::$orm);
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

        static::assertIsArray($result);
        static::assertSame($expected, $result);
    }

    public function test_load_type_mapping_config(): void
    {
        $configPath = __DIR__ . '/type_mapping_config.json';
        $config = VersaModel::loadTypeMappingConfig($configPath);

        static::assertIsArray($config);
        static::assertArrayHasKey('json_field', $config);
        static::assertArrayHasKey('uuid_field', $config);
        static::assertArrayHasKey('array_field', $config);
        static::assertSame('json', $config['json_field']['type']);
        static::assertSame('uuid', $config['uuid_field']['type']);
        static::assertSame('array', $config['array_field']['type']);
    }

    public function test_load_type_mapping_config_file_not_found(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Type mapping configuration file not found:');

        VersaModel::loadTypeMappingConfig('/nonexistent/path.json');
    }

    public function test_load_type_mapping_config_invalid_json(): void
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

    public function test_settimezone_affects_gettimezone_and_date_casting(): void
    {
        $orm = self::$orm;

        // Establecer timezone
        $orm->setTimezone('America/Mexico_City');
        static::assertSame('America/Mexico_City', $orm->getTimezone());

        // Definir un modelo con propertyTypes para forzar cast a datetime
        $modelClass = new class('tz_table', $orm) extends VersaModel {
            public static function propertyTypes(): array
            {
                return ['any' => ['type' => 'datetime']];
            }
        };
        // Crear instancia (anónima ya instanciada)
        $model = $modelClass;
        $timestamp = 1700000000; // unix timestamp fijo

        $phpDt = $model->castToPhpType('any', $timestamp);
        static::assertInstanceOf(\DateTimeInterface::class, $phpDt);
        static::assertSame('America/Mexico_City', $phpDt->getTimezone()->getName());
    }
}
