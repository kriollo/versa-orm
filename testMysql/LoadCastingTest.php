<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use DateTime;
use VersaORM\VersaModel;

use function get_class;

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
        self::$orm->exec('INSERT INTO load_cast_test (name, active, created_at) VALUES (?, ?, ?)', [
            'Test User',
            1,
            '2025-08-12 10:30:00',
        ]);
    }

    public function test_load_method_applies_casting(): void
    {
        // Modelo con tipado fuerte
        $model = new class ('load_cast_test', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'integer'],
                    'name' => ['type' => 'string'],
                    'active' => ['type' => 'bool'],
                    'created_at' => ['type' => 'datetime'],
                ];
            }
        };

        // Usar el método load() que tenía el bug
        $loaded = $model::load('load_cast_test', 1);

        self::assertNotNull($loaded, 'load() should return an instance');
        self::assertInstanceOf(get_class($model), $loaded, 'load() should return instance of correct class');

        // Verificar que export() aplica casting correctamente
        $data = $loaded->export();

        self::assertIsInt($data['id'], 'id should be cast to integer');
        self::assertIsString($data['name'], 'name should be cast to string');
        self::assertIsBool($data['active'], 'active should be cast to boolean');
        self::assertTrue($data['active'], 'active should be true when value is 1');
        self::assertInstanceOf(DateTime::class, $data['created_at'], 'created_at should be cast to DateTime');

        // Verificar valores específicos
        self::assertSame(1, $data['id']);
        self::assertSame('Test User', $data['name']);
        self::assertSame('2025-08-12 10:30:00', $data['created_at']->format('Y-m-d H:i:s'));
    }

    public function test_load_method_with_update(): void
    {
        // Modelo con tipado fuerte
        $model = new class ('load_cast_test', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'integer'],
                    'name' => ['type' => 'string'],
                    'active' => ['type' => 'bool'],
                    'created_at' => ['type' => 'datetime'],
                ];
            }
        };

        // Cargar, modificar y guardar
        $loaded = $model::load('load_cast_test', 1);
        self::assertNotNull($loaded);

        // Verificar que active se carga correctamente como boolean true
        $loadedData = $loaded->export();
        self::assertTrue($loadedData['active']);

        $loaded->name = 'Updated User';
        $loaded->store(); // Esto debe manejar DateTime correctamente y preservar otros campos

        // Recargar y verificar que el valor active se preservó
        $reloaded = $model::load('load_cast_test', 1);
        self::assertNotNull($reloaded);

        $data = $reloaded->export();
        self::assertSame('Updated User', $data['name']);
        self::assertIsBool($data['active']);
        self::assertTrue($data['active'], 'El campo active debe preservarse cuando solo se modifica otro campo');
    }

    public function test_load_method_with_update_boolean(): void
    {
        // Modelo con tipado fuerte
        $model = new class ('load_cast_test', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'integer'],
                    'name' => ['type' => 'string'],
                    'active' => ['type' => 'bool'],
                    'created_at' => ['type' => 'datetime'],
                ];
            }

            protected array $rules = [
                'active' => ['required'],
            ];
        };

        // Cargar, modificar y guardar
        $loaded = $model::load('load_cast_test', 1);
        self::assertNotNull($loaded);

        // Verificar que active se carga correctamente como boolean true
        $loadedData = $loaded->export();
        self::assertTrue($loadedData['active']);

        // Negar el valor de active (toggle)
        $originalActive = $loaded->active;
        $loaded->active = ! $loaded->active;
        $loaded->store(); // Esto debe manejar el cambio de boolean correctamente

        // Recargar y verificar que el valor active se actualizó correctamente
        $reloaded = $model::load('load_cast_test', 1);
        self::assertNotNull($reloaded);

        $data = $reloaded->export();
        self::assertIsBool($data['active']);
        self::assertFalse($data['active'], 'El campo active debe haberse cambiado de true a false');
        self::assertNotSame($originalActive, $data['active'], 'El valor debe haber cambiado');
    }

    public function test_load_method_with_boolean_validation_edge_cases(): void
    {
        // Modelo con tipado fuerte y validación required
        $model = new class ('load_cast_test', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'integer'],
                    'name' => ['type' => 'string'],
                    'active' => ['type' => 'bool'],
                    'created_at' => ['type' => 'datetime'],
                ];
            }

            protected array $rules = [
                'active' => ['required'],
            ];
        };

        // Test 1: Cambiar de true a false debe funcionar
        $loaded = $model::load('load_cast_test', 1);
        self::assertNotNull($loaded);

        $loaded->active = false;
        $loaded->store(); // No debe fallar la validación

        $reloaded = $model::load('load_cast_test', 1);
        self::assertFalse($reloaded->active);

        // Test 2: Cambiar de false a true debe funcionar
        $loaded->active = true;
        $loaded->store(); // No debe fallar la validación

        $reloaded = $model::load('load_cast_test', 1);
        self::assertTrue($reloaded->active);

        // Test 3: Asignar null debe fallar la validación (puede ser por tipo o required)
        $loaded->active = null;

        $this->expectException(\VersaORM\VersaORMException::class);
        $this->expectExceptionMessageMatches('/The active (field is required|must be a boolean value)/');
        $loaded->store();
    }
}
