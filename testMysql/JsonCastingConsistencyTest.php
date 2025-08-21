<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

use function get_class;

require_once __DIR__ . '/TestCase.php';
/**
 * @group mysql
 */
class JsonCastingConsistencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::$orm->exec('DROP TABLE IF EXISTS configs_json_cast');
        self::$orm->schemaCreate('configs_json_cast', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(50)', 'nullable' => false],
            ['name' => 'settings', 'type' => 'TEXT', 'nullable' => false],
        ]);
        self::$orm->table('configs_json_cast')->insert(['name' => 'conf_a', 'settings' => '{"theme":"dark","lang":"es"}']);
    }

    public function test_json_casting_consistency(): void
    {
        $model = new class ('configs_json_cast', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'int'],
                    'name' => ['type' => 'string'],
                    'settings' => ['type' => 'json'],
                ];
            }
        };

        $rows = self::$orm->table('configs_json_cast', get_class($model))->get();
        self::assertCount(1, $rows);
        self::assertIsArray($rows[0]['settings']);
        self::assertSame('dark', $rows[0]['settings']['theme']);

        $first = self::$orm->table('configs_json_cast', get_class($model))->firstArray();
        self::assertNotNull($first);
        self::assertIsArray($first['settings']);

        $objects = self::$orm->table('configs_json_cast', get_class($model))->findAll();
        self::assertIsArray($objects[0]->export()['settings']);

        $one = self::$orm->table('configs_json_cast', get_class($model))->where('name', '=', 'conf_a')->findOne();
        self::assertNotNull($one);
        self::assertIsArray($one->export()['settings']);
    }
}
