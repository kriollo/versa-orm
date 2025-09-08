<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\EventDispatcher;

/**
 * @group sqlite
 */
final class EventDispatcherInterfaceTest extends TestCase
{
    public function test_interface_methods_exist(): void
    {
        self::assertTrue(interface_exists('\VersaORM\EventDispatcher'));
        $r = new ReflectionClass(EventDispatcher::class);

        self::assertTrue($r->hasMethod('listen'));
        self::assertTrue($r->hasMethod('dispatch'));
    }
}
