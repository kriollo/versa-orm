<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaModel;

use function get_class;

require_once __DIR__ . '/TestCase.php';
/**
 * @group sqlite
 */
class BooleanCastingConsistencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Crear tabla específica para este test
        self::$orm->exec('DROP TABLE IF EXISTS users_bool_cast');
        self::$orm->schemaCreate('users_bool_cast', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'TEXT', 'nullable' => false],
            ['name' => 'status', 'type' => 'INTEGER', 'nullable' => false, 'default' => 0], // SQLite usa INTEGER para boolean
        ]);
        self::$orm->table('users_bool_cast')->insert(['name' => 'A', 'status' => 1]);
        self::$orm->table('users_bool_cast')->insert(['name' => 'B', 'status' => 0]);
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
        self::assertIsArray($rows);
        self::assertCount(2, $rows);

        foreach ($rows as $r) {
            self::assertIsBool($r['status'], 'El campo status no fue casteado a boolean en get()');
        }

        // 2. firstArray()
        $first = self::$orm->table('users_bool_cast', get_class($model))->firstArray();
        self::assertNotNull($first);
        self::assertIsBool($first['status'], 'El campo status no fue casteado a boolean en firstArray()');

        // 3. findAll() (objetos) -> export() debe dar bool
        $objects = self::$orm->table('users_bool_cast', get_class($model))->findAll();
        self::assertCount(2, $objects);

        foreach ($objects as $o) {
            $data = $o->export();
            self::assertIsBool($data['status'], 'El campo status no fue casteado a boolean en export()');
        }

        // 4. findOne()
        $one = self::$orm->table('users_bool_cast', get_class($model))->where('name', '=', 'A')->findOne();
        self::assertNotNull($one);
        self::assertIsBool($one->export()['status'], 'El campo status no fue casteado a boolean en findOne()');
    }
}
