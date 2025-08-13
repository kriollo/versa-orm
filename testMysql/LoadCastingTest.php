<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';
/**
 * @group mysql
 */
class LoadCastingTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Crear tabla específica para este test
        self::$orm->exec('DROP TABLE IF EXISTS load_cast_test');
        self::$orm->schemaCreate('load_cast_test', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(50)', 'nullable' => false],
            ['name' => 'active', 'type' => 'TINYINT', 'nullable' => false, 'default' => 0],
            ['name' => 'created_at', 'type' => 'DATETIME', 'nullable' => true],
        ]);
        self::$orm->exec("INSERT INTO load_cast_test (name, active, created_at) VALUES (?, ?, ?)", [
            'Test User',
            1,
            '2025-08-12 10:30:00'
        ]);
    }

    public function testLoadMethodAppliesCasting(): void
    {
        // Modelo con tipado fuerte
        $model = new class('load_cast_test', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'integer'],
                    'name' => ['type' => 'string'],
                    'active' => ['type' => 'boolean'],
                    'created_at' => ['type' => 'datetime'],
                ];
            }
        };

        // Usar el método load() que tenía el bug
        $loaded = $model::load('load_cast_test', 1);

        $this->assertNotNull($loaded, 'load() should return an instance');
        $this->assertInstanceOf(get_class($model), $loaded, 'load() should return instance of correct class');

        // Verificar que export() aplica casting correctamente
        $data = $loaded->export();

        $this->assertIsInt($data['id'], 'id should be cast to integer');
        $this->assertIsString($data['name'], 'name should be cast to string');
        $this->assertIsBool($data['active'], 'active should be cast to boolean');
        $this->assertTrue($data['active'], 'active should be true when value is 1');
        $this->assertInstanceOf(\DateTime::class, $data['created_at'], 'created_at should be cast to DateTime');

        // Verificar valores específicos
        $this->assertEquals(1, $data['id']);
        $this->assertEquals('Test User', $data['name']);
        $this->assertEquals('2025-08-12 10:30:00', $data['created_at']->format('Y-m-d H:i:s'));
    }

    public function testLoadMethodWithUpdate(): void
    {
        // Modelo con tipado fuerte
        $model = new class('load_cast_test', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'integer'],
                    'name' => ['type' => 'string'],
                    'active' => ['type' => 'boolean'],
                    'created_at' => ['type' => 'datetime'],
                ];
            }
        };

        // Cargar, modificar y guardar
        $loaded = $model::load('load_cast_test', 1);
        $this->assertNotNull($loaded);

        // Verificar que active se carga correctamente como boolean true
        $loadedData = $loaded->export();
        $this->assertTrue($loadedData['active']);

        $loaded->name = 'Updated User';
        $loaded->store(); // Esto debe manejar DateTime correctamente y preservar otros campos

        // Recargar y verificar que el valor active se preservó
        $reloaded = $model::load('load_cast_test', 1);
        $this->assertNotNull($reloaded);

        $data = $reloaded->export();
        $this->assertEquals('Updated User', $data['name']);
        $this->assertIsBool($data['active']);
        $this->assertTrue($data['active'], 'El campo active debe preservarse cuando solo se modifica otro campo');
    }
}
