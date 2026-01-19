<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\VersaSchema;
use VersaORM\VersaModel;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

class FeaturesTestModel extends VersaModel
{
    protected string $table = 'test_table';

    protected array $fillable = ['name', 'age'];

    public function __construct($orm = null)
    {
        parent::__construct($this->table, $orm);
    }
}

class InferredModel extends VersaModel {}

/**
 * @group core
 */
class VersaModelFeaturesTest extends TestCase
{
    private $orm;

    protected function setUp(): void
    {
        $this->orm = $this->createMock(VersaORM::class);
        $this->orm->method('getConfig')->willReturn(['driver' => 'sqlite']);
        VersaModel::setORM($this->orm);
        FeaturesTestModel::clearEventListeners();
    }

    public function test_table_name_inference(): void
    {
        $model = new FeaturesTestModel($this->orm);
        self::assertSame('test_table', $model->tableName());

        $model2 = new InferredModel('inferredmodels', $this->orm);
        self::assertSame('inferredmodels', $model2->tableName());
    }

    public function test_event_listeners(): void
    {
        $called = false;
        FeaturesTestModel::on('creating', function ($model, $event) use (&$called) {
            $called = true;
        });

        $model = new FeaturesTestModel($this->orm);

        // Trigger event via reflection since it's protected
        $refl = new \ReflectionClass(VersaModel::class);
        $method = $refl->getMethod('fireEvent');
        $method->setAccessible(true);
        $method->invoke($model, 'creating');

        self::assertTrue($called);
    }

    public function test_freeze_logic(): void
    {
        $model = new FeaturesTestModel($this->orm);

        // Mock freezeModel and isModelFrozen
        $this->orm
            ->expects(self::once())
            ->method('freezeModel')
            ->with(FeaturesTestModel::class, true);
        $this->orm
            ->expects(self::once())
            ->method('isModelFrozen')
            ->with(FeaturesTestModel::class)
            ->willReturn(true);

        FeaturesTestModel::freeze(true);
        self::assertTrue(FeaturesTestModel::isFrozen());
    }

    public function test_fill_mass_assignment(): void
    {
        $model = new FeaturesTestModel($this->orm);

        // This should pass
        $model->fill(['name' => 'John', 'age' => 30]);
        self::assertSame('John', $model->name);
        self::assertSame(30, $model->age);

        // This should throw because 'secret' is not in fillable
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage("Field 'secret' is not fillable");
        $model->fill(['secret' => 'hacker']);
    }

    public function test_casting_cache(): void
    {
        $model = new FeaturesTestModel($this->orm);
        $model->name = 'John';

        // First access triggers casting
        self::assertSame('John', $model->name);
        // Second access should use cache (checked via coverage)
        self::assertSame('John', $model->name);
    }

    public function test_type_mapping_conversion(): void
    {
        $model = new FeaturesTestModel($this->orm);

        $json = $model->convertValueByTypeMapping('meta', '{"a":1}', ['type' => 'json']);
        self::assertSame(['a' => 1], $json);

        $uuid = $model->convertValueByTypeMapping('u', 'uuid-string', ['type' => 'uuid']);
        self::assertSame('uuid-string', $uuid);

        $arr = $model->convertValueByTypeMapping('tags', 'a,b', ['type' => 'array']);
        self::assertSame(['a,b'], $arr); // explode is for set/enum

        $enum = $model->convertValueByTypeMapping('status', 'active,inactive', ['type' => 'enum']);
        self::assertSame(['active', 'inactive'], $enum);
    }

    public function test_load_type_mapping_config_throws_if_missing(): void
    {
        $this->expectException(VersaORMException::class);
        FeaturesTestModel::loadTypeMappingConfig('/non/existent.json');
    }

    public function test_versa_schema_facade(): void
    {
        VersaSchema::setORM($this->orm);

        $this->orm
            ->expects(self::once())
            ->method('schemaRename')
            ->with('old', 'new');
        VersaSchema::rename('old', 'new');
    }

    public function test_orm_accessors(): void
    {
        $model = new FeaturesTestModel($this->orm);
        self::assertSame($this->orm, $model->orm());
        self::assertSame($this->orm, $model->db());
    }

    public function test_validate_calls_internal_methods(): void
    {
        // This targets the validate lines
        $model = new FeaturesTestModel($this->orm);
        $errors = $model->validate();
        self::assertIsArray($errors);
    }
}
