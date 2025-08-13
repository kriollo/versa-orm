<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

class FreezeModeTest extends TestCase
{
    public function testFreezeGlobalToggle(): void
    {
        $orm = self::$orm;

        // Estado inicial
        self::assertFalse($orm->isFrozen());

        // Activar y verificar
        $orm->freeze(true);
        self::assertTrue($orm->isFrozen());

        // Desactivar y verificar
        $orm->freeze(false);
        self::assertFalse($orm->isFrozen());
    }

    public function testFreezePerModel(): void
    {
        $orm = self::$orm;

        // Definir un modelo inline de pruebas
        $modelClass = __NAMESPACE__ . '\FreezeDummyModel';

        if (!class_exists($modelClass)) {
            eval('namespace ' . __NAMESPACE__ . '; class FreezeDummyModel extends \VersaORM\VersaModel { public function __construct($orm=null){ parent::__construct("test_users", $orm ?? \VersaORM\VersaModel::getGlobalORM()); } }');
        }

        // Asegurar global off
        $orm->freeze(false);
        self::assertFalse($orm->isFrozen());

        // Marcar el modelo como frozen
        $orm->freezeModel($modelClass, true);
        self::assertTrue($orm->isModelFrozen($modelClass));

        // Quitar freeze del modelo
        $orm->freezeModel($modelClass, false);
        self::assertFalse($orm->isModelFrozen($modelClass));
    }

    public function testModelStaticHelpers(): void
    {
        $orm = self::$orm;

        // Definir un modelo inline y set global ORM
        $modelClass = __NAMESPACE__ . '\FreezeStaticModel';

        if (!class_exists($modelClass)) {
            eval('namespace ' . __NAMESPACE__ . '; class FreezeStaticModel extends \VersaORM\VersaModel { public function __construct($orm=null){ parent::__construct("test_users", $orm ?? \VersaORM\VersaModel::getGlobalORM()); } }');
        }

        VersaModel::setORM($orm);

        // Usar helpers estáticos
        $modelClass::freeze(true);
        self::assertTrue($modelClass::isFrozen());

        $modelClass::freeze(false);
        self::assertFalse($modelClass::isFrozen());
    }
}

// Dummy model simple
class TestModel extends VersaModel
{
    public function __construct($orm = null)
    {
        parent::__construct('test_users', $orm ?? VersaModel::getGlobalORM());
    }
}
