<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

class VersaORMTest extends TestCase
{
    public function testCoreClassLoads(): void
    {
        self::assertTrue(class_exists('\\VersaORM\\VersaORM'));
    }
}
