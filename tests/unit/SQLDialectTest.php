<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

class SQLDialectTest extends TestCase
{
    public function testDialectClassExists(): void
    {
        self::assertTrue(
            class_exists('\\VersaORM\\SQL\\Dialects\\MySQLDialect')
            || class_exists('\\VersaORM\\SQL\\Dialects\\PostgreSQLDialect'),
        );
    }
}
