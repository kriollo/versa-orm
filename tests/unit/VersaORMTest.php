<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\VersaModel;
use VersaORM\VersaORM;

class VersaORMTest extends TestCase
{
    public function testCoreClassLoads(): void
    {
        self::assertTrue(class_exists('\\VersaORM\\VersaORM'));
    }

    public function testSetAndGetConfig(): void
    {
        $orm = new VersaORM();
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $orm->setConfig($cfg);
        $this->assertSame($cfg, $orm->getConfig());
    }

    public function testTimezoneSetAndGet(): void
    {
        $orm = new VersaORM();
        $orm->setTimezone('UTC');
        $this->assertSame('UTC', $orm->getTimezone());

        // cambiar y comprobar que se actualiza
        $orm->setTimezone('America/Mexico_City');
        $this->assertSame('America/Mexico_City', $orm->getTimezone());
    }

    public function testMetricsAndResetAreCallable(): void
    {
        $orm = new VersaORM(['engine' => 'pdo']);

        // metrics devuelve un array o null; para engine pdo debe ser array
        $metrics = $orm->metrics();
        $this->assertIsArray($metrics);

        // reset no debe lanzar
        $orm->metricsReset();
        $this->assertTrue(true);
    }

    public function testAddTypeConverterDelegatesToVersaModel(): void
    {
        $orm = new VersaORM();

        // Asegurarse de que no lanza excepciones al delegar
        VersaModel::addTypeConverter('test_conv', function ($s, $p, $v) { return $v; }, null);
        $orm->addTypeConverter('test_conv2', function ($s, $p, $v) { return $v; }, null);

        $this->assertTrue(true);
    }
}
