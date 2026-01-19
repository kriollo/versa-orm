<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Traits;

use Exception;
use PHPUnit\Framework\TestCase;
use VersaORM\Traits\VersaORMTrait;
use VersaORM\VersaORM;

class VersaORMTraitTestClass
{
    use VersaORMTrait;

    // Make DEFAULT_CONFIG public for testing if needed, or just use it as is
}

/**
 * @group core
 */
class VersaORMTraitTest extends TestCase
{
    protected function setUp(): void
    {
        global $config;
        $config = null;
    }

    public function test_connect_orm_throws_exception_if_no_config(): void
    {
        $obj = new VersaORMTraitTestClass();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Database configuration not found');

        $obj->connectORM();
    }

    public function test_connect_orm_throws_exception_if_missing_fields(): void
    {
        global $config;
        $config = ['DB' => ['DB_DRIVER' => 'sqlite']]; // missing others

        $obj = new VersaORMTraitTestClass();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Database configuration field 'DB_HOST' is missing");

        $obj->connectORM();
    }

    public function test_connect_orm_success_and_disconnect(): void
    {
        global $config;
        $config = [
            'DB' => [
                'DB_DRIVER' => 'sqlite',
                'DB_HOST' => 'localhost',
                'DB_PORT' => 0,
                'DB_NAME' => ':memory:',
                'DB_USER' => '',
                'DB_PASS' => '',
                'debug' => true,
            ],
        ];

        $obj = new VersaORMTraitTestClass();
        $obj->connectORM();

        static::assertInstanceOf(VersaORM::class, $obj->getORM());

        $obj->disconnectORM();
        static::assertNull($obj->getORM());
    }
}
