<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\Traits\VersaORMTrait;
use VersaORM\VersaORM;

require_once __DIR__ . '/../../vendor/autoload.php';

// Este test carga explícitamente el archivo del trait para asegurar que
// el generador de cobertura (clover) lo relacione con las líneas ejecutadas
class VersaORMTraitIncludeTest extends TestCase
{
    public function testIncludeTraitFileAndBasicUse(): void
    {
        // Forzar la inclusión absoluta del archivo (la ruta relativa en CI puede variar)
        $traitPath = __DIR__ . '/../../src/Traits/VersaORMTrait.php';
        self::assertFileExists($traitPath, 'VersaORMTrait.php debe existir en src/Traits');

        require_once $traitPath;

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

        $obj = new class () {
            use VersaORMTrait;

            public function callGetORM(): ?VersaORM
            {
                return $this->getORM();
            }
        };

        try {
            $obj->connectORM();
            $orm = $obj->callGetORM();
            $this->assertInstanceOf(VersaORM::class, $orm);
            $obj->disconnectORM();
            $this->assertNull($obj->callGetORM());
        } finally {
            if ($prev === null) {
                unset($GLOBALS['config']);
            } else {
                $GLOBALS['config'] = $prev;
            }
        }
    }
}
