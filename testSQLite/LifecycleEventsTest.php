<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\ModelEvent;
use VersaORM\VersaModel;

class LifecycleEventsTest extends TestCase
{
    private static $table = 'users';

    protected function setUp(): void
    {
        TestCase::createSchema();
        TestCase::$orm->exec('DELETE FROM users');
        if (method_exists(VersaModel::class, 'clearEventListeners')) {
            VersaModel::clearEventListeners();
        }
    }

    public function test_creating_event_listener_is_called()
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

    public function test_created_event_listener_is_called()
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

    public function test_updating_event_listener_is_called()
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

    public function test_deleting_event_listener_is_called()
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

    public function test_cancel_operation_from_listener()
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

    public function test_magic_method_is_called()
    {
        $called = false;
        $model = new class(self::$table, TestCase::$orm) extends VersaModel {
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
