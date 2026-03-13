<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

class VersaModelMinimalTest extends TestCase
{
    public function testModelClassExists(): void
    {
        static::assertTrue(class_exists('\\VersaORM\\VersaModel'));
    }
}
