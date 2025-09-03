<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

use function get_class;

require_once __DIR__ . '/TestCase.php';
/**
 * @group postgresql
 */
class BooleanCastingConsistencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Crear tabla específica para este test
        self::$orm->exec('DROP TABLE IF EXISTS users_bool_cast');
        self::$orm->schemaCreate('users_bool_cast', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(50)', 'nullable' => false],
            ['name' => 'status', 'type' => 'BOOLEAN', 'nullable' => false, 'default' => false],
        ]);
        self::$orm->table('users_bool_cast')->insert(['name' => 'A', 'status' => true]);
        self::$orm->table('users_bool_cast')->insert(['name' => 'B', 'status' => false]);
    }

    public function test_boolean_casting_consistent_across_paths(): void
    {
        // Modelo con tipado fuerte
        $model = new class('users_bool_cast', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'int'],
                    'name' => ['type' => 'string'],
                    'status' => ['type' => 'bool'],
                ];
            }
        };

        // 1. Obtener arrays (API) -> debe devolver bool
        $rows = self::$orm->table('users_bool_cast', get_class($model))->get();
        static::assertIsArray($rows);
        static::assertCount(2, $rows);

        foreach ($rows as $r) {
            static::assertIsBool($r['status'], 'El campo status no fue casteado a boolean en get()');
        }

        // 2. firstArray()
        $first = self::$orm->table('users_bool_cast', get_class($model))->firstArray();
        static::assertNotNull($first);
        static::assertIsBool($first['status'], 'El campo status no fue casteado a boolean en firstArray()');

        // 3. findAll() (objetos) -> export() debe dar bool
        $objects = self::$orm->table('users_bool_cast', get_class($model))->findAll();
        static::assertCount(2, $objects);

        foreach ($objects as $o) {
            $data = $o->export();
            static::assertIsBool($data['status'], 'El campo status no fue casteado a boolean en export()');
        }

        // 4. findOne()
        $one = self::$orm->table('users_bool_cast', get_class($model))->where('name', '=', 'A')->findOne();
        static::assertNotNull($one);
        static::assertIsBool($one->export()['status'], 'El campo status no fue casteado a boolean en findOne()');
    }
}
