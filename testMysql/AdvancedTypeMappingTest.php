<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;
use VersaORM\VersaORMException;

require_once __DIR__ . '/TestCase.php';
/**
 * @group mysql
 */
class AdvancedTypeMappingTest extends TestCase
{
    public function test_json_type_conversion(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $jsonString = '{"key": "value"}';
        $fieldSchema = ['type' => 'json'];

        $result = $model->convertValueByTypeMapping('json_field', $jsonString, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['key' => 'value'], $result);
    }

    public function test_json_type_conversion_with_already_decoded_data(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $arrayData = ['key' => 'value'];
        $fieldSchema = ['type' => 'json'];

        $result = $model->convertValueByTypeMapping('json_field', $arrayData, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['key' => 'value'], $result);
    }

    public function test_uuid_type_conversion(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        $fieldSchema = ['type' => 'uuid'];

        $result = $model->convertValueByTypeMapping('uuid_field', $uuid, $fieldSchema);

        self::assertIsString($result);
        self::assertSame($uuid, $result);
    }

    public function test_array_type_conversion_from_json_string(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $arrayData = '["value1", "value2"]';
        $fieldSchema = ['type' => 'array'];

        $result = $model->convertValueByTypeMapping('array_field', $arrayData, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['value1', 'value2'], $result);
    }

    public function test_array_type_conversion_from_array(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $arrayData = ['value1', 'value2'];
        $fieldSchema = ['type' => 'array'];

        $result = $model->convertValueByTypeMapping('array_field', $arrayData, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['value1', 'value2'], $result);
    }

    public function test_array_type_conversion_from_scalar_value(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $scalarValue = 'single_value';
        $fieldSchema = ['type' => 'array'];

        $result = $model->convertValueByTypeMapping('array_field', $scalarValue, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['single_value'], $result);
    }

    public function test_set_type_conversion_from_comma_separated(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $setValue = 'option1,option2,option3';
        $fieldSchema = ['type' => 'set'];

        $result = $model->convertValueByTypeMapping('set_field', $setValue, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['option1', 'option2', 'option3'], $result);
    }

    public function test_enum_type_conversion_from_comma_separated(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $enumValue = 'active,pending';
        $fieldSchema = ['type' => 'enum'];

        $result = $model->convertValueByTypeMapping('enum_field', $enumValue, $fieldSchema);

        self::assertIsArray($result);
        self::assertSame(['active', 'pending'], $result);
    }

    public function test_unknown_type_returns_original_value(): void
    {
        $model = new VersaModel('test_table', self::$orm);
        $value = 'some_value';
        $fieldSchema = ['type' => 'unknown_type'];

        $result = $model->convertValueByTypeMapping('unknown_field', $value, $fieldSchema);

        self::assertSame('some_value', $result);
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

        self::assertIsArray($result);
        self::assertSame($expected, $result);
    }

    public function test_load_type_mapping_config(): void
    {
        $configPath = __DIR__ . '/type_mapping_config.json';
        $config = VersaModel::loadTypeMappingConfig($configPath);

        self::assertIsArray($config);
        self::assertArrayHasKey('json_field', $config);
        self::assertArrayHasKey('uuid_field', $config);
        self::assertArrayHasKey('array_field', $config);
        self::assertSame('json', $config['json_field']['type']);
        self::assertSame('uuid', $config['uuid_field']['type']);
        self::assertSame('array', $config['array_field']['type']);
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

    public function test_runtime_money_converter_registration(): void
    {
        // Registrar un conversor 'money' que convierte centavos a float y viceversa
        $orm = self::$orm;

        $orm->addTypeConverter(
            'money',
            // php handler: cents (int) -> float
            function ($s, $p, $v, $_ = []) {
                if (is_int($v) || ctype_digit((string) $v)) {
                    return (int) $v / 100.0;
                }

                if (is_string($v) && preg_match('/^\d+(?:\.\d+)?$/', $v)) {
                    return (float) $v;
                }

                return (float) $v;
            },
            // db handler: float -> integer cents
            function ($s, $p, $v, $_ = []) {
                return (int) round((float) $v * 100);
            },
        );

        // Definir un modelo de prueba con propertyTypes
        $modelClass = new class('money_table', $orm) extends \VersaORM\VersaModel {
            public static function propertyTypes(): array
            {
                return ['amount' => ['type' => 'money']];
            }
        };

        // Crear instancia y comprobar conversiones directas
        $model = $modelClass;

        $dbVal = $model->castToDatabaseType('amount', 123.45);
        self::assertSame(12345, $dbVal);

        $phpVal = $model->castToPhpType('amount', 12345);
        self::assertIsFloat($phpVal);
        self::assertSame(123.45, $phpVal);
    }

    public function test_settimezone_affects_gettimezone_and_date_casting(): void
    {
        $orm = self::$orm;

        // Establecer timezone
        $orm->setTimezone('America/Mexico_City');
        self::assertSame('America/Mexico_City', $orm->getTimezone());

        // Definir un modelo con propertyTypes para forzar cast a datetime
        $modelClass = new class('tz_table', $orm) extends \VersaORM\VersaModel {
            public static function propertyTypes(): array
            {
                return ['any' => ['type' => 'datetime']];
            }
        };
        // Crear instancia (anónima ya instanciada)
        $model = $modelClass;
        $timestamp = 1700000000; // unix timestamp fijo

        $phpDt = $model->castToPhpType('any', $timestamp);
        self::assertInstanceOf(\DateTimeInterface::class, $phpDt);
        self::assertSame('America/Mexico_City', $phpDt->getTimezone()->getName());
    }
}
