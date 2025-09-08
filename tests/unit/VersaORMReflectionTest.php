<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
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

        self::assertSame('NULL', $mFormat->invoke($orm, null, 'mysql'));
        self::assertSame('1', $mFormat->invoke($orm, true, 'mysql'));
        self::assertSame('TRUE', $mFormat->invoke($orm, true, 'sqlite'));
        self::assertSame("'O''Reilly'", $mFormat->invoke($orm, "O'Reilly", 'sqlite'));

        $mQuote = $r->getMethod('quoteIdent');
        $mQuote->setAccessible(true);

        self::assertSame('`col`', $mQuote->invoke($orm, 'col', 'mysql'));
        self::assertSame('"col"', $mQuote->invoke($orm, 'col', 'sqlite'));

        $mIsDdl = $r->getMethod('isDdlOperation');
        $mIsDdl->setAccessible(true);

        self::assertTrue($mIsDdl->invoke($orm, 'createTable'));
        self::assertFalse($mIsDdl->invoke($orm, 'query'));

        $mIsRaw = $r->getMethod('isRawQueryDDL');
        $mIsRaw->setAccessible(true);

        self::assertTrue($mIsRaw->invoke($orm, 'CREATE TABLE test (id INT)'));
        self::assertFalse($mIsRaw->invoke($orm, 'SELECT * FROM t'));
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
        self::assertTrue($orm->isFrozen());

        // validateFreezeOperation should throw for DDL when frozen
        $mValidate = $r->getMethod('validateFreezeOperation');
        $mValidate->setAccessible(true);

        $this->expectException(VersaORMException::class);
        $mValidate->invoke($orm, 'createTable');
    }
}
