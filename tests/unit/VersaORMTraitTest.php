<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use Exception;
use PHPUnit\Framework\TestCase;
use VersaORM\Traits\VersaORMTrait;
use VersaORM\VersaORM;

require_once __DIR__ . '/../../vendor/autoload.php';

class VersaORMTraitTest extends TestCase
{
    public function testConnectORMThrowsWhenGlobalConfigMissing(): void
    {
        // Ensure global config is not set
        if (isset($GLOBALS['config'])) {
            unset($GLOBALS['config']);
        }

        $obj = new class() {
            use VersaORMTrait;

            // expose protected getORM for assertions (already public in trait)
        };

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Database configuration not found');

        $obj->connectORM();
    }

    public function testConnectAndDisconnectWithValidConfig(): void
    {
        // Prepare a minimal valid DB config expected by the trait
        $prev = $GLOBALS['config'] ?? null;

        $GLOBALS['config'] = [
            'DB' => [
                'DB_DRIVER' => 'sqlite',
                'DB_HOST' => 'localhost',
                'DB_PORT' => 0,
                'DB_NAME' => ':memory:',
                'DB_USER' => '',
                'DB_PASS' => '',
                'debug' => false,
            ],
        ];

        $obj = new class() {
            use VersaORMTrait;

            // helper to expose internal ORM for assertions
            public function getOrmPublic(): null|VersaORM
            {
                return $this->getORM();
            }
        };

        try {
            $obj->connectORM();

            $orm = $obj->getOrmPublic();
            static::assertInstanceOf(VersaORM::class, $orm);

            // disconnect should clean the instance
            $obj->disconnectORM();
            static::assertNull($obj->getOrmPublic());
        } finally {
            // restore previous global config
            if ($prev === null) {
                unset($GLOBALS['config']);
            } else {
                $GLOBALS['config'] = $prev;
            }
        }
    }
}
