<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

class BooleanCastingConsistencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Crear tabla específica para este test
        self::$orm->exec('DROP TABLE IF EXISTS users_bool_cast');
        self::$orm->schemaCreate('users_bool_cast', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(50)', 'nullable' => false],
            ['name' => 'status', 'type' => 'TINYINT', 'nullable' => false, 'default' => 0],
        ]);
        self::$orm->table('users_bool_cast')->insert(['name' => 'A', 'status' => 1]);
        self::$orm->table('users_bool_cast')->insert(['name' => 'B', 'status' => 0]);
    }

    public function testBooleanCastingConsistentAcrossPaths(): void
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
        $this->assertIsArray($rows);
        $this->assertCount(2, $rows);
        foreach ($rows as $r) {
            $this->assertIsBool($r['status'], 'El campo status no fue casteado a boolean en get()');
        }

        // 2. firstArray()
        $first = self::$orm->table('users_bool_cast', get_class($model))->firstArray();
        $this->assertNotNull($first);
        $this->assertIsBool($first['status'], 'El campo status no fue casteado a boolean en firstArray()');

        // 3. findAll() (objetos) -> export() debe dar bool
        $objects = self::$orm->table('users_bool_cast', get_class($model))->findAll();
        $this->assertCount(2, $objects);
        foreach ($objects as $o) {
            $data = $o->export();
            $this->assertIsBool($data['status'], 'El campo status no fue casteado a boolean en export()');
        }

        // 4. findOne()
        $one = self::$orm->table('users_bool_cast', get_class($model))->where('name', '=', 'A')->findOne();
        $this->assertNotNull($one);
        $this->assertIsBool($one->export()['status'], 'El campo status no fue casteado a boolean en findOne()');
    }
}
