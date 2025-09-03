<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaModel;
use VersaORM\VersaORMException;

/**
 * Port de tests de tipado fuerte (driver agnóstico) para SQLite.
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

    public function test_cast_int(): void
    {
        static::assertSame(123, $this->model->castToPhpType('id', '123'));
    }

    public function test_cast_json(): void
    {
        $arr = $this->model->castToPhpType('settings', '{"a":1}');
        static::assertSame(['a' => 1], $arr);
    }

    public function test_invalid_json(): void
    {
        $this->expectException(VersaORMException::class);
        $this->model->castToPhpType('settings', '{bad json');
    }

    public function test_uuid_validation(): void
    {
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        static::assertSame($uuid, $this->model->castToPhpType('uuid', $uuid));
    }

    public function test_invalid_uuid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->model->castToPhpType('uuid', 'not-a-uuid');
    }

    public function test_enum_valid(): void
    {
        static::assertSame('active', $this->model->castToPhpType('status', 'active'));
    }

    public function test_enum_invalid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->model->castToPhpType('status', 'zzz');
    }

    public function test_set_valid(): void
    {
        static::assertSame(['work', 'personal'], $this->model->castToPhpType('tags', 'work,personal'));
    }

    public function test_set_invalid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->model->castToPhpType('tags', 'work,invalid');
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

class TestTypedModel extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name' => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
            'settings' => ['type' => 'json', 'nullable' => true],
            'uuid' => ['type' => 'uuid', 'nullable' => false],
            'status' => ['type' => 'enum', 'values' => ['active', 'inactive'], 'default' => 'active'],
            'tags' => ['type' => 'set', 'values' => ['work', 'personal', 'urgent']],
            'created_at' => ['type' => 'datetime', 'nullable' => true],
        ];
    }
}
