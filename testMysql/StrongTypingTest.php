<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use DateTime;
use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORMException;

/**
 * Test para funcionalidad de tipado fuerte en VersaORM.
 */
/**
 * @group mysql
 */
class StrongTypingTest extends TestCase
{
    private TestTypedModel $model;

    protected function setUp(): void
    {
        $this->model = new TestTypedModel('test_table', null);
    }

    protected function tearDown(): void
    {
        TestTypedModel::clearPropertyTypesCache();
    }

    public function test_get_property_types_returns_correct_types(): void
    {
        $propertyTypes = TestTypedModel::getPropertyTypes();

        static::assertIsArray($propertyTypes);
        static::assertArrayHasKey('id', $propertyTypes);
        static::assertArrayHasKey('name', $propertyTypes);
        static::assertArrayHasKey('email', $propertyTypes);
        static::assertArrayHasKey('settings', $propertyTypes);
        static::assertArrayHasKey('uuid', $propertyTypes);
        static::assertArrayHasKey('status', $propertyTypes);
        static::assertArrayHasKey('tags', $propertyTypes);
        static::assertArrayHasKey('created_at', $propertyTypes);

        static::assertSame('int', $propertyTypes['id']['type']);
        static::assertSame('string', $propertyTypes['name']['type']);
        static::assertSame('json', $propertyTypes['settings']['type']);
        static::assertSame('uuid', $propertyTypes['uuid']['type']);
        static::assertSame('enum', $propertyTypes['status']['type']);
        static::assertSame('set', $propertyTypes['tags']['type']);
        static::assertSame('datetime', $propertyTypes['created_at']['type']);
    }

    public function test_cast_to_php_type_with_int(): void
    {
        $result = $this->model->castToPhpType('id', '123');
        static::assertSame(123, $result);
        static::assertIsInt($result);
    }

    public function test_cast_to_php_type_with_float(): void
    {
        $model = new TestTypedModelWithFloat('test_table', null);
        $result = $model->castToPhpType('price', '19.99');
        static::assertSame(19.99, $result);
        static::assertIsFloat($result);
    }

    public function test_cast_to_php_type_with_string(): void
    {
        $result = $this->model->castToPhpType('name', 123);
        static::assertSame('123', $result);
        static::assertIsString($result);
    }

    public function test_cast_to_php_type_with_bool(): void
    {
        $model = new TestTypedModelWithBool('test_table', null);

        static::assertTrue($model->castToPhpType('active', '1'));
        static::assertTrue($model->castToPhpType('active', 'true'));
        static::assertTrue($model->castToPhpType('active', 'yes'));
        static::assertTrue($model->castToPhpType('active', 'on'));
        static::assertFalse($model->castToPhpType('active', '0'));
        static::assertFalse($model->castToPhpType('active', 'false'));
        static::assertFalse($model->castToPhpType('active', 0));
    }

    public function test_cast_to_php_type_with_json(): void
    {
        $jsonString = '{"key": "value", "number": 42}';
        $result = $this->model->castToPhpType('settings', $jsonString);

        static::assertIsArray($result);
        static::assertSame(['key' => 'value', 'number' => 42], $result);
    }

    public function test_cast_to_php_type_with_invalid_json(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid JSON for property settings');

        $this->model->castToPhpType('settings', '{invalid json}');
    }

    public function test_cast_to_php_type_with_uuid(): void
    {
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        $result = $this->model->castToPhpType('uuid', $uuid);

        static::assertSame($uuid, $result);
    }

    public function test_cast_to_php_type_with_invalid_uuid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid UUID format for property uuid');

        $this->model->castToPhpType('uuid', 'not-a-uuid');
    }

    public function test_cast_to_php_type_with_date_time(): void
    {
        $result = $this->model->castToPhpType('created_at', '2023-01-01 12:00:00');

        static::assertInstanceOf(DateTime::class, $result);
        static::assertSame('2023-01-01 12:00:00', $result->format('Y-m-d H:i:s'));
    }

    public function test_cast_to_php_type_with_enum(): void
    {
        $result = $this->model->castToPhpType('status', 'active');
        static::assertSame('active', $result);
    }

    public function test_cast_to_php_type_with_invalid_enum(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid enum value for property status');

        $this->model->castToPhpType('status', 'invalid_status');
    }

    public function test_cast_to_php_type_with_set(): void
    {
        $result = $this->model->castToPhpType('tags', 'work,personal');
        static::assertSame(['work', 'personal'], $result);
    }

    public function test_cast_to_php_type_with_invalid_set(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid set value');

        $this->model->castToPhpType('tags', 'work,invalid_tag');
    }

    public function test_cast_to_php_type_with_array(): void
    {
        $model = new TestTypedModelWithArray('test_table', null);
        $jsonArray = '["item1", "item2", "item3"]';
        $result = $model->castToPhpType('items', $jsonArray);

        static::assertIsArray($result);
        static::assertSame(['item1', 'item2', 'item3'], $result);
    }

    public function test_cast_to_database_type_with_int(): void
    {
        $result = $this->model->castToDatabaseType('id', '123');
        static::assertSame(123, $result);
    }

    public function test_cast_to_database_type_with_string(): void
    {
        $result = $this->model->castToDatabaseType('name', 123);
        static::assertSame('123', $result);
    }

    public function test_cast_to_database_type_with_string_too_long(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('String too long for property name');

        $longString = str_repeat('a', 300); // Assuming max_length is 255
        $this->model->castToDatabaseType('name', $longString);
    }

    public function test_cast_to_database_type_with_bool(): void
    {
        $model = new TestTypedModelWithBool('test_table', null);

        static::assertSame(1, $model->castToDatabaseType('active', true));
        static::assertSame(0, $model->castToDatabaseType('active', false));
    }

    public function test_cast_to_database_type_with_json(): void
    {
        $data = ['key' => 'value', 'number' => 42];
        $result = $this->model->castToDatabaseType('settings', $data);

        static::assertIsString($result);
        static::assertSame('{"key":"value","number":42}', $result);
    }

    public function test_cast_to_database_type_with_date_time(): void
    {
        $dateTime = new DateTime('2023-01-01 12:00:00');
        $result = $this->model->castToDatabaseType('created_at', $dateTime);

        static::assertSame('2023-01-01 12:00:00', $result);
    }

    public function test_cast_to_database_type_with_enum(): void
    {
        $result = $this->model->castToDatabaseType('status', 'active');
        static::assertSame('active', $result);
    }

    public function test_cast_to_database_type_with_set(): void
    {
        $result = $this->model->castToDatabaseType('tags', ['work', 'personal']);
        static::assertSame('work,personal', $result);
    }

    public function test_cast_to_database_type_with_uuid(): void
    {
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        $result = $this->model->castToDatabaseType('uuid', $uuid);
        static::assertSame($uuid, $result);
    }

    public function test_cast_to_database_type_with_invalid_uuid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid UUID format for property uuid');

        $this->model->castToDatabaseType('uuid', 'not-a-uuid');
    }

    public function test_cast_to_php_type_with_null_value(): void
    {
        $result = $this->model->castToPhpType('name', null);
        static::assertNull($result);
    }

    public function test_cast_to_database_type_with_null_value(): void
    {
        $result = $this->model->castToDatabaseType('name', null);
        static::assertNull($result);
    }

    public function test_cast_to_php_type_with_undefined_property(): void
    {
        $result = $this->model->castToPhpType('undefined_property', 'some_value');
        static::assertSame('some_value', $result);
    }

    public function test_clear_property_types_cache(): void
    {
        // Primero obtener los tipos para llenar el caché
        TestTypedModel::getPropertyTypes();

        // Limpiar la caché
        TestTypedModel::clearPropertyTypesCache();

        // El cache debería estar limpio, pero los tipos deberían ser los mismos
        $propertyTypes = TestTypedModel::getPropertyTypes();
        static::assertIsArray($propertyTypes);
        static::assertArrayHasKey('id', $propertyTypes);
    }

    public function test_mutators_and_accessors(): void
    {
        $model = new TestTypedModelWithMutators('test_table', null);

        $mutators = $model->getMutators();
        $accessors = $model->getAccessors();

        static::assertIsArray($mutators);
        static::assertIsArray($accessors);
        static::assertArrayHasKey('name', $mutators);
        static::assertArrayHasKey('name', $accessors);
    }

    public function test_cast_with_inet_type(): void
    {
        $model = new TestTypedModelWithInet('test_table', null);

        $result = $model->castToPhpType('ip_address', '192.168.1.1');
        static::assertSame('192.168.1.1', $result);

        $result = $model->castToDatabaseType('ip_address', '192.168.1.1');
        static::assertSame('192.168.1.1', $result);
    }

    public function test_cast_with_invalid_inet_type(): void
    {
        $model = new TestTypedModelWithInet('test_table', null);

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid IP address for property ip_address');

        $model->castToPhpType('ip_address', 'not-an-ip');
    }
}

/**
 * Modelo de prueba para testing de tipado fuerte.
 */
class TestTypedModel extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name' => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
            'email' => ['type' => 'string', 'max_length' => 255, 'nullable' => false, 'unique' => true],
            'settings' => ['type' => 'json', 'nullable' => true],
            'uuid' => ['type' => 'uuid', 'nullable' => false],
            'status' => ['type' => 'enum', 'values' => ['active', 'inactive'], 'default' => 'active'],
            'tags' => ['type' => 'set', 'values' => ['work', 'personal', 'urgent']],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
            'updated_at' => ['type' => 'datetime', 'nullable' => true],
        ];
    }
}

/**
 * Modelo de prueba con tipo float.
 */
class TestTypedModelWithFloat extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'price' => ['type' => 'float', 'nullable' => false],
        ];
    }
}

/**
 * Modelo de prueba con tipo bool.
 */
class TestTypedModelWithBool extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'active' => ['type' => 'bool', 'nullable' => false],
        ];
    }
}

/**
 * Modelo de prueba con mutadores y accesorios.
 */
class TestTypedModelWithMutators extends VersaModel
{
    protected array $mutators = [
        'name' => 'strtoupper',
    ];

    protected array $accessors = [
        'name' => 'strtolower',
    ];

    protected static function definePropertyTypes(): array
    {
        return [
            'name' => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
        ];
    }
}

/**
 * Modelo de prueba con tipo inet.
 */
class TestTypedModelWithInet extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'ip_address' => ['type' => 'inet', 'nullable' => false],
        ];
    }
}

/**
 * Modelo de prueba con tipo array.
 */
class TestTypedModelWithArray extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'items' => ['type' => 'array', 'nullable' => false],
        ];
    }
}
