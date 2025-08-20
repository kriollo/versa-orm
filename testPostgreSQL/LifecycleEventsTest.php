<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\ModelEvent;
use VersaORM\VersaModel;

class LifecycleEventsTest extends TestCase
{
    private static $table = 'users';

    public function setUp(): void
    {
        TestCase::createSchema();
        TestCase::$orm->exec('DELETE FROM users');
        if (method_exists(VersaModel::class, 'clearEventListeners')) {
            VersaModel::clearEventListeners();
        }
    }

    public function testCreatingEventListenerIsCalled()
    {
        $called = false;
        VersaModel::on('creating', function ($model, ModelEvent $event) use (&$called) {
            $called = true;
        });
        $model = VersaModel::dispense(self::$table);
        $model->name = 'Test';
        $model->email = 'test_' . uniqid() . '@example.com';
        $model->status = 'active';
        $model->store();
        $this->assertTrue($called, 'Listener de creating fue llamado');
    }

    public function testCreatedEventListenerIsCalled()
    {
        $called = false;
        VersaModel::on('created', function ($model, ModelEvent $event) use (&$called) {
            $called = true;
        });
        $model = VersaModel::dispense(self::$table);
        $model->name = 'Test';
        $model->email = 'test_' . uniqid() . '@example.com';
        $model->status = 'active';
        $model->store();
        $this->assertTrue($called, 'Listener de created fue llamado');
    }

    public function testUpdatingEventListenerIsCalled()
    {
        $called = false;
        VersaModel::on('updating', function ($model, ModelEvent $event) use (&$called) {
            $called = true;
        });
        $model = VersaModel::dispense(self::$table);
        $model->name = 'Test';
        $model->email = 'test_' . uniqid() . '@example.com';
        $model->status = 'active';
        $model->store();
        $model->name = 'Updated';
        $model->store();
        $this->assertTrue($called, 'Listener de updating fue llamado');
    }

    public function testDeletingEventListenerIsCalled()
    {
        $called = false;
        VersaModel::on('deleting', function ($model, ModelEvent $event) use (&$called) {
            $called = true;
        });
        $model = VersaModel::dispense(self::$table);
        $model->name = 'Test';
        $model->email = 'test_' . uniqid() . '@example.com';
        $model->status = 'active';
        $model->store();
        $model->trash();
        $this->assertTrue($called, 'Listener de deleting fue llamado');
    }

    public function testCancelOperationFromListener()
    {
        VersaModel::on('creating', function ($model, ModelEvent $event) {
            $event->cancel = true;
        });
        $model = VersaModel::dispense(self::$table);
        $model->name = 'Test';
        $model->email = 'test_' . uniqid() . '@example.com';
        $model->status = 'active';
        $result = $model->store();
        $this->assertNull($result, 'La operación fue cancelada por el listener');
    }

    public function testMagicMethodIsCalled()
    {
        $called = false;
        $model = new class (self::$table, TestCase::$orm) extends VersaModel {
            public function beforeCreate()
            {
                global $called;
                $called = true;
            }
        };
        $model->name = 'Test';
        $model->email = 'test_' . uniqid() . '@example.com';
        $model->status = 'active';
        $model->store();
        $this->assertTrue($GLOBALS['called'], 'Método mágico beforeCreate fue llamado');
    }
}
