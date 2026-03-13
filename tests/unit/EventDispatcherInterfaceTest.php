<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\EventDispatcher;

/**
 * @group sqlite
 */
final class EventDispatcherInterfaceTest extends TestCase
{
    public function test_interface_methods_exist(): void
    {
        static::assertTrue(interface_exists('\VersaORM\EventDispatcher'));
        $r = new ReflectionClass(EventDispatcher::class);

        static::assertTrue($r->hasMethod('listen'));
        static::assertTrue($r->hasMethod('dispatch'));
    }
}
