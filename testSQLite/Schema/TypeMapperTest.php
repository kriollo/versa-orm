<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\TypeMapper;

/**
 * Test para el TypeMapper que maneja la conversión de tipos entre motores.
 *
 * @group sqlite
 */
class TypeMapperTest extends TestCase
{
    public function testCanMapBasicTypes(): void
    {
        // MySQL
        static::assertEquals('VARCHAR', TypeMapper::mapType('string', 'mysql'));
        static::assertEquals('INT', TypeMapper::mapType('integer', 'mysql'));
        static::assertEquals('BIGINT', TypeMapper::mapType('bigInteger', 'mysql'));
        static::assertEquals('TEXT', TypeMapper::mapType('text', 'mysql'));
        static::assertEquals('TINYINT(1)', TypeMapper::mapType('boolean', 'mysql'));
        static::assertEquals('JSON', TypeMapper::mapType('json', 'mysql'));

        // PostgreSQL
        static::assertEquals('VARCHAR', TypeMapper::mapType('string', 'postgresql'));
        static::assertEquals('INTEGER', TypeMapper::mapType('integer', 'postgresql'));
        static::assertEquals('BIGINT', TypeMapper::mapType('bigInteger', 'postgresql'));
        static::assertEquals('TEXT', TypeMapper::mapType('text', 'postgresql'));
        static::assertEquals('BOOLEAN', TypeMapper::mapType('boolean', 'postgresql'));
        static::assertEquals('JSON', TypeMapper::mapType('json', 'postgresql'));

        // SQLite
        static::assertEquals('TEXT', TypeMapper::mapType('string', 'sqlite'));
        static::assertEquals('INTEGER', TypeMapper::mapType('integer', 'sqlite'));
        static::assertEquals('INTEGER', TypeMapper::mapType('bigInteger', 'sqlite'));
        static::assertEquals('TEXT', TypeMapper::mapType('text', 'sqlite'));
        static::assertEquals('INTEGER', TypeMapper::mapType('boolean', 'sqlite'));
        static::assertEquals('TEXT', TypeMapper::mapType('json', 'sqlite'));
    }

    public function testCanMapTypesWithOptions(): void
    {
        // String con longitud
        static::assertEquals('VARCHAR(100)', TypeMapper::mapType('string', 'mysql', ['length' => 100]));
        static::assertEquals('VARCHAR(100)', TypeMapper::mapType('string', 'postgresql', ['length' => 100]));
        static::assertEquals('TEXT', TypeMapper::mapType('string', 'sqlite', ['length' => 100]));

        // Decimal con precisión
        static::assertEquals('DECIMAL(10,2)', TypeMapper::mapType('decimal', 'mysql', [
            'precision' => 10,
            'scale' => 2,
        ]));
        static::assertEquals('DECIMAL(10,2)', TypeMapper::mapType('decimal', 'postgresql', [
            'precision' => 10,
            'scale' => 2,
        ]));
        static::assertEquals('NUMERIC(10,2)', TypeMapper::mapType('decimal', 'sqlite', [
            'precision' => 10,
            'scale' => 2,
        ]));
    }

    public function testCanMapEnumTypes(): void
    {
        $values = ['active', 'inactive', 'pending'];

        // MySQL soporta ENUM nativo
        $mysqlEnum = TypeMapper::mapType('enum', 'mysql', ['values' => $values]);
        static::assertEquals("ENUM('active','inactive','pending')", $mysqlEnum);

        // PostgreSQL y SQLite usan VARCHAR/TEXT
        static::assertEquals('VARCHAR(255)', TypeMapper::mapType('enum', 'postgresql', ['values' => $values]));
        static::assertEquals('TEXT', TypeMapper::mapType('enum', 'sqlite', ['values' => $values]));
    }

    public function testCanMapSetTypes(): void
    {
        $values = ['read', 'write', 'execute'];

        // MySQL soporta SET nativo
        $mysqlSet = TypeMapper::mapType('set', 'mysql', ['values' => $values]);
        static::assertEquals("SET('read','write','execute')", $mysqlSet);

        // PostgreSQL y SQLite usan TEXT
        static::assertEquals('TEXT', TypeMapper::mapType('set', 'postgresql', ['values' => $values]));
        static::assertEquals('TEXT', TypeMapper::mapType('set', 'sqlite', ['values' => $values]));
    }

    public function testCanMapIncrementTypes(): void
    {
        // MySQL
        static::assertEquals('BIGINT UNSIGNED', TypeMapper::mapType('bigIncrements', 'mysql'));
        static::assertEquals('INT UNSIGNED', TypeMapper::mapType('increments', 'mysql'));

        // PostgreSQL
        static::assertEquals('BIGSERIAL', TypeMapper::mapType('bigIncrements', 'postgresql'));
        static::assertEquals('SERIAL', TypeMapper::mapType('increments', 'postgresql'));

        // SQLite
        static::assertEquals('INTEGER', TypeMapper::mapType('bigIncrements', 'sqlite'));
        static::assertEquals('INTEGER', TypeMapper::mapType('increments', 'sqlite'));
    }

    public function testCanMapSpecialTypes(): void
    {
        // IP Address
        static::assertEquals('VARCHAR(45)', TypeMapper::mapType('ipAddress', 'mysql'));
        static::assertEquals('INET', TypeMapper::mapType('ipAddress', 'postgresql'));
        static::assertEquals('TEXT', TypeMapper::mapType('ipAddress', 'sqlite'));

        // MAC Address
        static::assertEquals('VARCHAR(17)', TypeMapper::mapType('macAddress', 'mysql'));
        static::assertEquals('MACADDR', TypeMapper::mapType('macAddress', 'postgresql'));
        static::assertEquals('TEXT', TypeMapper::mapType('macAddress', 'sqlite'));

        // UUID
        static::assertEquals('CHAR(36)', TypeMapper::mapType('uuid', 'mysql'));
        static::assertEquals('UUID', TypeMapper::mapType('uuid', 'postgresql'));
        static::assertEquals('TEXT', TypeMapper::mapType('uuid', 'sqlite'));
    }

    public function testCanGetSupportedTypes(): void
    {
        $mysqlTypes = TypeMapper::getSupportedTypes('mysql');
        $postgresTypes = TypeMapper::getSupportedTypes('postgresql');
        $sqliteTypes = TypeMapper::getSupportedTypes('sqlite');

        static::assertIsArray($mysqlTypes);
        static::assertIsArray($postgresTypes);
        static::assertIsArray($sqliteTypes);

        static::assertContains('string', $mysqlTypes);
        static::assertContains('integer', $mysqlTypes);
        static::assertContains('boolean', $mysqlTypes);

        static::assertContains('string', $postgresTypes);
        static::assertContains('integer', $postgresTypes);
        static::assertContains('boolean', $postgresTypes);

        static::assertContains('string', $sqliteTypes);
        static::assertContains('integer', $sqliteTypes);
        static::assertContains('boolean', $sqliteTypes);
    }

    public function testCanCheckTypeSupport(): void
    {
        static::assertTrue(TypeMapper::isTypeSupported('string', 'mysql'));
        static::assertTrue(TypeMapper::isTypeSupported('integer', 'postgresql'));
        static::assertTrue(TypeMapper::isTypeSupported('boolean', 'sqlite'));

        static::assertFalse(TypeMapper::isTypeSupported('nonexistent', 'mysql'));
        static::assertFalse(TypeMapper::isTypeSupported('string', 'nonexistent'));
    }

    public function testCanGetTypeCompatibility(): void
    {
        $stringCompatibility = TypeMapper::getTypeCompatibility('string');

        static::assertIsArray($stringCompatibility);
        static::assertArrayHasKey('mysql', $stringCompatibility);
        static::assertArrayHasKey('postgresql', $stringCompatibility);
        static::assertArrayHasKey('sqlite', $stringCompatibility);

        static::assertEquals('VARCHAR', $stringCompatibility['mysql']);
        static::assertEquals('VARCHAR', $stringCompatibility['postgresql']);
        static::assertEquals('TEXT', $stringCompatibility['sqlite']);
    }

    public function testThrowsExceptionForUnsupportedDriver(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported database driver: unknown');

        TypeMapper::mapType('string', 'unknown');
    }

    public function testThrowsExceptionForUnsupportedType(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported column type: nonexistent');

        TypeMapper::mapType('nonexistent', 'mysql');
    }

    public function testCanMapMultipleTypes(): void
    {
        // morphs devuelve array para _id y _type
        $morphs = TypeMapper::mapType('morphs', 'mysql');
        static::assertIsArray($morphs);
        static::assertCount(2, $morphs);
        static::assertEquals('BIGINT UNSIGNED', $morphs[0]);
        static::assertEquals('VARCHAR(255)', $morphs[1]);

        // timestamps devuelve array para created_at y updated_at
        $timestamps = TypeMapper::mapType('timestamps', 'mysql');
        static::assertIsArray($timestamps);
        static::assertCount(2, $timestamps);
        static::assertEquals('TIMESTAMP', $timestamps[0]);
        static::assertEquals('TIMESTAMP', $timestamps[1]);
    }
}
