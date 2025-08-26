<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\SQL\PdoEngine;
use VersaORM\VersaORM;

class VersaORMHelpersTest extends TestCase
{
    public function testQuoteIdentAndFormatDefault(): void
    {
        $orm = new VersaORM();
        $orm->setConfig(['driver' => 'mysql', 'database' => ':memory:']);

        $r = new \ReflectionClass($orm);
        $mQuote = $r->getMethod('quoteIdent');
        $mQuote->setAccessible(true);
        $quoted = $mQuote->invoke($orm, 'col', 'mysql');
        $this->assertStringContainsString('`', $quoted);

        $mFormat = $r->getMethod('formatDefault');
        $mFormat->setAccessible(true);
        $this->assertSame('NULL', $mFormat->invoke($orm, null, 'mysql'));
        $this->assertSame('1', $mFormat->invoke($orm, true, 'mysql'));
        $this->assertSame('TRUE', $mFormat->invoke($orm, true, 'postgres'));
        $this->assertSame("'abc'", $mFormat->invoke($orm, 'abc', 'sqlite'));
    }

    public function testIsDdlOperationAndIsRawQueryDDL(): void
    {
        $orm = new VersaORM();
        $r = new \ReflectionClass($orm);
        $mDdl = $r->getMethod('isDdlOperation');
        $mDdl->setAccessible(true);
        $this->assertTrue($mDdl->invoke($orm, 'createTable'));
        $this->assertFalse($mDdl->invoke($orm, 'query'));

        $mRaw = $r->getMethod('isRawQueryDDL');
        $mRaw->setAccessible(true);
        $this->assertTrue($mRaw->invoke($orm, 'CREATE TABLE x (id INT)'));
        $this->assertFalse($mRaw->invoke($orm, 'SELECT 1'));
    }

    public function testPdoEngineInvalidateCacheByPattern(): void
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($cfg);

        $res = $engine->execute('cache', ['action' => 'enable']);
        $this->assertSame('cache enabled', $res);

        // Invalidate without table on sqlite should skip gracefully
        $res2 = $engine->execute('cache', ['action' => 'invalidate']);
        $this->assertStringContainsString('skipped', (string) $res2);
    }
}
