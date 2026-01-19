<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

use function get_class;

require_once __DIR__ . '/TestCase.php';
/**
 * @group mysql
 */
class EnumSetCastingConsistencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::$orm->exec('DROP TABLE IF EXISTS labels_enum_cast');
        // Usar VARCHAR para simular enum/set almacenados como texto (se espera que el modelo normalice)
        self::$orm->schemaCreate('labels_enum_cast', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'status', 'type' => 'VARCHAR(50)', 'nullable' => false],
            ['name' => 'tags', 'type' => 'VARCHAR(255)', 'nullable' => true],
        ]);
        // Insertar valores representativos
        self::$orm->table('labels_enum_cast')->insert(['status' => 'active', 'tags' => 'work,urgent']);
        self::$orm->table('labels_enum_cast')->insert(['status' => 'inactive', 'tags' => 'personal']);
    }

    public function test_enum_set_casting_consistency(): void
    {
        $model = new class('labels_enum_cast', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'int'],
                    'status' => ['type' => 'enum', 'values' => ['active', 'inactive']],
                    'tags' => ['type' => 'set', 'values' => ['work', 'urgent', 'personal']],
                ];
            }
        };

        $rows = self::$orm->table('labels_enum_cast', get_class($model))->get();
        static::assertCount(2, $rows);

        foreach ($rows as $r) {
            static::assertIsString($r['status']);
            static::assertIsArray($r['tags']);
        }

        $first = self::$orm->table('labels_enum_cast', get_class($model))->firstArray();
        static::assertNotNull($first);
        static::assertIsString($first['status']);
        static::assertIsArray($first['tags']);

        $objects = self::$orm->table('labels_enum_cast', get_class($model))->findAll();

        foreach ($objects as $o) {
            $data = $o->export();
            static::assertIsString($data['status']);
            static::assertIsArray($data['tags']);
        }

        $one = self::$orm->table('labels_enum_cast', get_class($model))->where('status', '=', 'active')->findOne();
        static::assertNotNull($one);
        static::assertIsArray($one->export()['tags']);
    }
}
