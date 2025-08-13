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

    public function testEnumSetCastingConsistency(): void
    {
        $model = new class('labels_enum_cast', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id'     => ['type' => 'int'],
                    'status' => ['type' => 'enum', 'values' => ['active', 'inactive']],
                    'tags'   => ['type' => 'set', 'values' => ['work', 'urgent', 'personal']],
                ];
            }
        };

        $rows = self::$orm->table('labels_enum_cast', get_class($model))->get();
        self::assertCount(2, $rows);

        foreach ($rows as $r) {
            self::assertIsString($r['status']);
            self::assertIsArray($r['tags']);
        }

        $first = self::$orm->table('labels_enum_cast', get_class($model))->firstArray();
        self::assertNotNull($first);
        self::assertIsString($first['status']);
        self::assertIsArray($first['tags']);

        $objects = self::$orm->table('labels_enum_cast', get_class($model))->findAll();

        foreach ($objects as $o) {
            $data = $o->export();
            self::assertIsString($data['status']);
            self::assertIsArray($data['tags']);
        }

        $one = self::$orm->table('labels_enum_cast', get_class($model))->where('status', '=', 'active')->findOne();
        self::assertNotNull($one);
        self::assertIsArray($one->export()['tags']);
    }
}
