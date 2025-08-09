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

    public function testCastInt(): void
    {
        $this->assertSame(123, $this->model->castToPhpType('id', '123'));
    }

    public function testCastJson(): void
    {
        $arr = $this->model->castToPhpType('settings', '{"a":1}');
        $this->assertEquals(['a' => 1], $arr);
    }

    public function testInvalidJson(): void
    {
        $this->expectException(VersaORMException::class);
        $this->model->castToPhpType('settings', '{bad json');
    }

    public function testUuidValidation(): void
    {
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        $this->assertSame($uuid, $this->model->castToPhpType('uuid', $uuid));
    }

    public function testInvalidUuid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->model->castToPhpType('uuid', 'not-a-uuid');
    }

    public function testEnumValid(): void
    {
        $this->assertSame('active', $this->model->castToPhpType('status', 'active'));
    }

    public function testEnumInvalid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->model->castToPhpType('status', 'zzz');
    }

    public function testSetValid(): void
    {
        $this->assertEquals(['work', 'personal'], $this->model->castToPhpType('tags', 'work,personal'));
    }

    public function testSetInvalid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->model->castToPhpType('tags', 'work,invalid');
    }
}

class TestTypedModel extends VersaModel
{
    protected static function definePropertyTypes(): array
    {
        return [
            'id'         => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name'       => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
            'settings'   => ['type' => 'json', 'nullable' => true],
            'uuid'       => ['type' => 'uuid', 'nullable' => false],
            'status'     => ['type' => 'enum', 'values' => ['active', 'inactive'], 'default' => 'active'],
            'tags'       => ['type' => 'set', 'values' => ['work', 'personal', 'urgent']],
            'created_at' => ['type' => 'datetime', 'nullable' => true],
        ];
    }
}
