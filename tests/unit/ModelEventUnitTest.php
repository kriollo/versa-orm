<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\ModelEvent;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Tests para ModelEvent - Eventos del modelo.
 */
class ModelEventUnitTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]);

        VersaModel::setORM($this->orm);

        // Crear tabla de prueba
        $this->orm->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR, email VARCHAR)');
        $this->orm->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Alice', 'alice@example.com']);
    }

    /**
     * Prueba crear un evento.
     */
    public function testCreateEvent(): void
    {
        $model = VersaModel::load('users', 1);

        $event = new ModelEvent($model, [], []);

        $this->assertNotNull($event);
    }

    /**
     * Prueba obtener modelo del evento.
     */
    public function testGetEventModel(): void
    {
        $model = VersaModel::load('users', 1);
        $event = new ModelEvent($model, [], []);

        $this->assertNotNull($event->model);
        $this->assertInstanceOf(VersaModel::class, $event->model);
    }

    /**
     * Prueba obtener datos originales del evento.
     */
    public function testGetEventOriginal(): void
    {
        $model = VersaModel::load('users', 1);
        $original = ['name' => 'Old Name'];
        $event = new ModelEvent($model, $original, []);

        $this->assertEquals($original, $event->original);
    }

    /**
     * Prueba obtener cambios del evento.
     */
    public function testGetEventChanges(): void
    {
        $model = VersaModel::load('users', 1);
        $changes = ['name' => 'New Name'];
        $event = new ModelEvent($model, [], $changes);

        $this->assertEquals($changes, $event->changes);
    }

    /**
     * Prueba marcar evento como cancelado.
     */
    public function testCancelEvent(): void
    {
        $model = VersaModel::load('users', 1);
        $event = new ModelEvent($model, [], []);

        $this->assertFalse($event->cancel);

        $event->cancel('Operation cancelled');

        $this->assertTrue($event->cancel);
        $this->assertEquals('Operation cancelled', $event->error);
    }

    /**
     * Prueba cancelar sin mensaje.
     */
    public function testCancelEventWithoutMessage(): void
    {
        $model = VersaModel::load('users', 1);
        $event = new ModelEvent($model, [], []);

        $event->cancel();

        $this->assertTrue($event->cancel);
        $this->assertNull($event->error);
    }
}
