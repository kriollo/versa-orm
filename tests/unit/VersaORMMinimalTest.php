<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

class VersaORMMinimalTest extends TestCase
{
    public function testVersaORMClassExists(): void
    {
        static::assertTrue(class_exists('\\VersaORM\\VersaORM'));
    }

    public function testVersaORMCanBeInstantiated(): void
    {
        $orm = new \VersaORM\VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        static::assertInstanceOf('\\VersaORM\\VersaORM', $orm);
    }
}
