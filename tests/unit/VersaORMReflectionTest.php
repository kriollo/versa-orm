<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

final class VersaORMReflectionTest extends TestCase
{
    public function test_formatDefault_and_quote_and_identifiers()
    {
        $orm = new VersaORM(['driver' => 'mysql']);

        $r = new ReflectionClass($orm);

        $mFormat = $r->getMethod('formatDefault');
        $mFormat->setAccessible(true);

        static::assertSame('NULL', $mFormat->invoke($orm, null, 'mysql'));
        static::assertSame('1', $mFormat->invoke($orm, true, 'mysql'));
        static::assertSame('TRUE', $mFormat->invoke($orm, true, 'sqlite'));
        static::assertSame("'O''Reilly'", $mFormat->invoke($orm, "O'Reilly", 'sqlite'));

        $mQuote = $r->getMethod('quoteIdent');
        $mQuote->setAccessible(true);

        static::assertSame('`col`', $mQuote->invoke($orm, 'col', 'mysql'));
        static::assertSame('"col"', $mQuote->invoke($orm, 'col', 'sqlite'));

        $mIsDdl = $r->getMethod('isDdlOperation');
        $mIsDdl->setAccessible(true);

        static::assertTrue($mIsDdl->invoke($orm, 'createTable'));
        static::assertFalse($mIsDdl->invoke($orm, 'query'));

        $mIsRaw = $r->getMethod('isRawQueryDDL');
        $mIsRaw->setAccessible(true);

        static::assertTrue($mIsRaw->invoke($orm, 'CREATE TABLE test (id INT)'));
        static::assertFalse($mIsRaw->invoke($orm, 'SELECT * FROM t'));
    }

    public function test_assertSafeIdentifier_and_errors()
    {
        $orm = new VersaORM(['driver' => 'mysql']);
        $r = new ReflectionClass($orm);

        $mAssert = $r->getMethod('assertSafeIdentifier');
        $mAssert->setAccessible(true);

        // Valid identifier does not throw
        $mAssert->invoke($orm, 'valid_name', 'column');

        // Invalid identifiers throw VersaORMException
        $this->expectException(VersaORMException::class);
        $mAssert->invoke($orm, 'bad name', 'column');
    }

    public function test_freeze_and_validateFreezeOperation_behaviour()
    {
        $orm = new VersaORM(['driver' => 'sqlite']);
        $r = new ReflectionClass($orm);

        // Freeze global
        $orm->freeze(true);
        static::assertTrue($orm->isFrozen());

        // validateFreezeOperation should throw for DDL when frozen
        $mValidate = $r->getMethod('validateFreezeOperation');
        $mValidate->setAccessible(true);

        $this->expectException(VersaORMException::class);
        $mValidate->invoke($orm, 'createTable');
    }
}
