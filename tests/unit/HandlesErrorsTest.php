<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

class HandlesErrorsTest extends TestCase
{
    public function testTraitIsAvailable(): void
    {
        self::assertTrue(trait_exists('\\VersaORM\\Traits\\HandlesErrors') || trait_exists('\\VersaORM\\Traits\\VersaORMTrait'));
    }
}
