<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

class FreezeModeTest extends TestCase
{
    public function test_freeze_global_toggle(): void
    {
        $orm = self::$orm;

        // Estado inicial
        static::assertFalse($orm->isFrozen());

        // Activar y verificar
        $orm->freeze(true);
        static::assertTrue($orm->isFrozen());

        // Desactivar y verificar
        $orm->freeze(false);
        static::assertFalse($orm->isFrozen());
    }

    public function test_freeze_per_model(): void
    {
        $orm = self::$orm;

        // Definir un modelo inline de pruebas
        $modelClass = __NAMESPACE__ . '\FreezeDummyModel';

        if (!class_exists($modelClass)) {
            eval('namespace '
                . __NAMESPACE__
                . '; class FreezeDummyModel extends \VersaORM\VersaModel { public function __construct($orm=null){ parent::__construct("test_users", $orm ?? \VersaORM\VersaModel::getGlobalORM()); } }');
        }

        // Asegurar global off
        $orm->freeze(false);
        static::assertFalse($orm->isFrozen());

        // Marcar el modelo como frozen
        $orm->freezeModel($modelClass, true);
        static::assertTrue($orm->isModelFrozen($modelClass));

        // Quitar freeze del modelo
        $orm->freezeModel($modelClass, false);
        static::assertFalse($orm->isModelFrozen($modelClass));
    }

    public function test_model_static_helpers(): void
    {
        $orm = self::$orm;

        // Definir un modelo inline y set global ORM
        $modelClass = __NAMESPACE__ . '\FreezeStaticModel';

        if (!class_exists($modelClass)) {
            eval('namespace '
                . __NAMESPACE__
                . '; class FreezeStaticModel extends \VersaORM\VersaModel { public function __construct($orm=null){ parent::__construct("test_users", $orm ?? \VersaORM\VersaModel::getGlobalORM()); } }');
        }

        VersaModel::setORM($orm);

        // Usar helpers estáticos
        $modelClass::freeze(true);
        static::assertTrue($modelClass::isFrozen());

        $modelClass::freeze(false);
        static::assertFalse($modelClass::isFrozen());
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
