<?php

declare(strict_types=1);

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

    public function testGetPropertyTypesReturnsCorrectTypes(): void
    {
        $propertyTypes = TestTypedModel::getPropertyTypes();

        $this->assertIsArray($propertyTypes);
        $this->assertArrayHasKey('id', $propertyTypes);
        $this->assertArrayHasKey('name', $propertyTypes);
        $this->assertArrayHasKey('email', $propertyTypes);
        $this->assertArrayHasKey('settings', $propertyTypes);
        $this->assertArrayHasKey('uuid', $propertyTypes);
        $this->assertArrayHasKey('status', $propertyTypes);
        $this->assertArrayHasKey('tags', $propertyTypes);
        $this->assertArrayHasKey('created_at', $propertyTypes);

        $this->assertEquals('int', $propertyTypes['id']['type']);
        $this->assertEquals('string', $propertyTypes['name']['type']);
        $this->assertEquals('json', $propertyTypes['settings']['type']);
        $this->assertEquals('uuid', $propertyTypes['uuid']['type']);
        $this->assertEquals('enum', $propertyTypes['status']['type']);
        $this->assertEquals('set', $propertyTypes['tags']['type']);
        $this->assertEquals('datetime', $propertyTypes['created_at']['type']);
    }

    public function testCastToPhpTypeWithInt(): void
    {
        $result = $this->model->castToPhpType('id', '123');
        $this->assertSame(123, $result);
        $this->assertIsInt($result);
    }

    public function testCastToPhpTypeWithFloat(): void
    {
        $model  = new TestTypedModelWithFloat('test_table', null);
        $result = $model->castToPhpType('price', '19.99');
        $this->assertSame(19.99, $result);
        $this->assertIsFloat($result);
    }

    public function testCastToPhpTypeWithString(): void
    {
        $result = $this->model->castToPhpType('name', 123);
        $this->assertSame('123', $result);
        $this->assertIsString($result);
    }

    public function testCastToPhpTypeWithBool(): void
    {
        $model = new TestTypedModelWithBool('test_table', null);

        $this->assertTrue($model->castToPhpType('active', '1'));
        $this->assertTrue($model->castToPhpType('active', 'true'));
        $this->assertTrue($model->castToPhpType('active', 'yes'));
        $this->assertTrue($model->castToPhpType('active', 'on'));
        $this->assertFalse($model->castToPhpType('active', '0'));
        $this->assertFalse($model->castToPhpType('active', 'false'));
        $this->assertFalse($model->castToPhpType('active', 0));
    }

    public function testCastToPhpTypeWithJson(): void
    {
        $jsonString = '{"key": "value", "number": 42}';
        $result     = $this->model->castToPhpType('settings', $jsonString);

        $this->assertIsArray($result);
        $this->assertEquals(['key' => 'value', 'number' => 42], $result);
    }

    public function testCastToPhpTypeWithInvalidJson(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid JSON for property settings');

        $this->model->castToPhpType('settings', '{invalid json}');
    }

    public function testCastToPhpTypeWithUuid(): void
    {
        $uuid   = '550e8400-e29b-41d4-a716-446655440000';
        $result = $this->model->castToPhpType('uuid', $uuid);

        $this->assertSame($uuid, $result);
    }

    public function testCastToPhpTypeWithInvalidUuid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid UUID format for property uuid');

        $this->model->castToPhpType('uuid', 'not-a-uuid');
    }

    public function testCastToPhpTypeWithDateTime(): void
    {
        $result = $this->model->castToPhpType('created_at', '2023-01-01 12:00:00');

        $this->assertInstanceOf(DateTime::class, $result);
        $this->assertEquals('2023-01-01 12:00:00', $result->format('Y-m-d H:i:s'));
    }

    public function testCastToPhpTypeWithEnum(): void
    {
        $result = $this->model->castToPhpType('status', 'active');
        $this->assertSame('active', $result);
    }

    public function testCastToPhpTypeWithInvalidEnum(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid enum value for property status');

        $this->model->castToPhpType('status', 'invalid_status');
    }

    public function testCastToPhpTypeWithSet(): void
    {
        $result = $this->model->castToPhpType('tags', 'work,personal');
        $this->assertEquals(['work', 'personal'], $result);
    }

    public function testCastToPhpTypeWithInvalidSet(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid set value');

        $this->model->castToPhpType('tags', 'work,invalid_tag');
    }

    public function testCastToPhpTypeWithArray(): void
    {
        $model     = new TestTypedModelWithArray('test_table', null);
        $jsonArray = '["item1", "item2", "item3"]';
        $result    = $model->castToPhpType('items', $jsonArray);

        $this->assertIsArray($result);
        $this->assertEquals(['item1', 'item2', 'item3'], $result);
    }

    public function testCastToDatabaseTypeWithInt(): void
    {
        $result = $this->model->castToDatabaseType('id', '123');
        $this->assertSame(123, $result);
    }

    public function testCastToDatabaseTypeWithString(): void
    {
        $result = $this->model->castToDatabaseType('name', 123);
        $this->assertSame('123', $result);
    }

    public function testCastToDatabaseTypeWithStringTooLong(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('String too long for property name');

        $longString = str_repeat('a', 300); // Assuming max_length is 255
        $this->model->castToDatabaseType('name', $longString);
    }

    public function testCastToDatabaseTypeWithBool(): void
    {
        $model = new TestTypedModelWithBool('test_table', null);

        $this->assertSame(1, $model->castToDatabaseType('active', true));
        $this->assertSame(0, $model->castToDatabaseType('active', false));
    }

    public function testCastToDatabaseTypeWithJson(): void
    {
        $data   = ['key' => 'value', 'number' => 42];
        $result = $this->model->castToDatabaseType('settings', $data);

        $this->assertIsString($result);
        $this->assertEquals('{"key":"value","number":42}', $result);
    }

    public function testCastToDatabaseTypeWithDateTime(): void
    {
        $dateTime = new DateTime('2023-01-01 12:00:00');
        $result   = $this->model->castToDatabaseType('created_at', $dateTime);

        $this->assertSame('2023-01-01 12:00:00', $result);
    }

    public function testCastToDatabaseTypeWithEnum(): void
    {
        $result = $this->model->castToDatabaseType('status', 'active');
        $this->assertSame('active', $result);
    }

    public function testCastToDatabaseTypeWithSet(): void
    {
        $result = $this->model->castToDatabaseType('tags', ['work', 'personal']);
        $this->assertSame('work,personal', $result);
    }

    public function testCastToDatabaseTypeWithUuid(): void
    {
        $uuid   = '550e8400-e29b-41d4-a716-446655440000';
        $result = $this->model->castToDatabaseType('uuid', $uuid);
        $this->assertSame($uuid, $result);
    }

    public function testCastToDatabaseTypeWithInvalidUuid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid UUID format for property uuid');

        $this->model->castToDatabaseType('uuid', 'not-a-uuid');
    }

    public function testCastToPhpTypeWithNullValue(): void
    {
        $result = $this->model->castToPhpType('name', null);
        $this->assertNull($result);
    }

    public function testCastToDatabaseTypeWithNullValue(): void
    {
        $result = $this->model->castToDatabaseType('name', null);
        $this->assertNull($result);
    }

    public function testCastToPhpTypeWithUndefinedProperty(): void
    {
        $result = $this->model->castToPhpType('undefined_property', 'some_value');
        $this->assertSame('some_value', $result);
    }

    public function testClearPropertyTypesCache(): void
    {
        // Primero obtener los tipos para llenar el caché
        TestTypedModel::getPropertyTypes();

        // Limpiar la caché
        TestTypedModel::clearPropertyTypesCache();

        // El cache debería estar limpio, pero los tipos deberían ser los mismos
        $propertyTypes = TestTypedModel::getPropertyTypes();
        $this->assertIsArray($propertyTypes);
        $this->assertArrayHasKey('id', $propertyTypes);
    }

    public function testMutatorsAndAccessors(): void
    {
        $model = new TestTypedModelWithMutators('test_table', null);

        $mutators  = $model->getMutators();
        $accessors = $model->getAccessors();

        $this->assertIsArray($mutators);
        $this->assertIsArray($accessors);
        $this->assertArrayHasKey('name', $mutators);
        $this->assertArrayHasKey('name', $accessors);
    }

    public function testCastWithInetType(): void
    {
        $model = new TestTypedModelWithInet('test_table', null);

        $result = $model->castToPhpType('ip_address', '192.168.1.1');
        $this->assertSame('192.168.1.1', $result);

        $result = $model->castToDatabaseType('ip_address', '192.168.1.1');
        $this->assertSame('192.168.1.1', $result);
    }

    public function testCastWithInvalidInetType(): void
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
            'id'         => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name'       => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
            'email'      => ['type' => 'string', 'max_length' => 255, 'nullable' => false, 'unique' => true],
            'settings'   => ['type' => 'json', 'nullable' => true],
            'uuid'       => ['type' => 'uuid', 'nullable' => false],
            'status'     => ['type' => 'enum', 'values' => ['active', 'inactive'], 'default' => 'active'],
            'tags'       => ['type' => 'set', 'values' => ['work', 'personal', 'urgent']],
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
