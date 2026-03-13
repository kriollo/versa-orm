<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\TypeMapper;

/**
 * Test para el TypeMapper que maneja la conversión de tipos entre motores.
 *
 * @group mysql
 */
class TypeMapperTest extends TestCase
{
    public function testCanMapBasicTypes(): void
    {
        // MySQL
        static::assertSame('VARCHAR', TypeMapper::mapType('string', 'mysql'));
        static::assertSame('INT', TypeMapper::mapType('integer', 'mysql'));
        static::assertSame('BIGINT', TypeMapper::mapType('bigInteger', 'mysql'));
        static::assertSame('TEXT', TypeMapper::mapType('text', 'mysql'));
        static::assertSame('TINYINT(1)', TypeMapper::mapType('boolean', 'mysql'));
        static::assertSame('JSON', TypeMapper::mapType('json', 'mysql'));

        // PostgreSQL
        static::assertSame('VARCHAR', TypeMapper::mapType('string', 'postgresql'));
        static::assertSame('INTEGER', TypeMapper::mapType('integer', 'postgresql'));
        static::assertSame('BIGINT', TypeMapper::mapType('bigInteger', 'postgresql'));
        static::assertSame('TEXT', TypeMapper::mapType('text', 'postgresql'));
        static::assertSame('BOOLEAN', TypeMapper::mapType('boolean', 'postgresql'));
        static::assertSame('JSON', TypeMapper::mapType('json', 'postgresql'));

        // SQLite
        static::assertSame('TEXT', TypeMapper::mapType('string', 'sqlite'));
        static::assertSame('INTEGER', TypeMapper::mapType('integer', 'sqlite'));
        static::assertSame('INTEGER', TypeMapper::mapType('bigInteger', 'sqlite'));
        static::assertSame('TEXT', TypeMapper::mapType('text', 'sqlite'));
        static::assertSame('INTEGER', TypeMapper::mapType('boolean', 'sqlite'));
        static::assertSame('TEXT', TypeMapper::mapType('json', 'sqlite'));
    }

    public function testCanMapTypesWithOptions(): void
    {
        // String con longitud
        static::assertSame('VARCHAR(100)', TypeMapper::mapType('string', 'mysql', ['length' => 100]));
        static::assertSame('VARCHAR(100)', TypeMapper::mapType('string', 'postgresql', ['length' => 100]));
        static::assertSame('TEXT', TypeMapper::mapType('string', 'sqlite', ['length' => 100]));

        // Decimal con precisión
        static::assertSame('DECIMAL(10,2)', TypeMapper::mapType('decimal', 'mysql', [
            'precision' => 10,
            'scale' => 2,
        ]));
        static::assertSame('DECIMAL(10,2)', TypeMapper::mapType('decimal', 'postgresql', [
            'precision' => 10,
            'scale' => 2,
        ]));
        static::assertSame('NUMERIC(10,2)', TypeMapper::mapType('decimal', 'sqlite', [
            'precision' => 10,
            'scale' => 2,
        ]));
    }

    public function testCanMapEnumTypes(): void
    {
        $values = ['active', 'inactive', 'pending'];

        // MySQL soporta ENUM nativo
        $mysqlEnum = TypeMapper::mapType('enum', 'mysql', ['values' => $values]);
        static::assertSame("ENUM('active','inactive','pending')", $mysqlEnum);

        // PostgreSQL y SQLite usan VARCHAR/TEXT
        static::assertSame('VARCHAR(255)', TypeMapper::mapType('enum', 'postgresql', ['values' => $values]));
        static::assertSame('TEXT', TypeMapper::mapType('enum', 'sqlite', ['values' => $values]));
    }

    public function testCanMapSetTypes(): void
    {
        $values = ['read', 'write', 'execute'];

        // MySQL soporta SET nativo
        $mysqlSet = TypeMapper::mapType('set', 'mysql', ['values' => $values]);
        static::assertSame("SET('read','write','execute')", $mysqlSet);

        // PostgreSQL y SQLite usan TEXT
        static::assertSame('TEXT', TypeMapper::mapType('set', 'postgresql', ['values' => $values]));
        static::assertSame('TEXT', TypeMapper::mapType('set', 'sqlite', ['values' => $values]));
    }

    public function testCanMapIncrementTypes(): void
    {
        // MySQL
        static::assertSame('BIGINT UNSIGNED', TypeMapper::mapType('bigIncrements', 'mysql'));
        static::assertSame('INT UNSIGNED', TypeMapper::mapType('increments', 'mysql'));

        // PostgreSQL
        static::assertSame('BIGSERIAL', TypeMapper::mapType('bigIncrements', 'postgresql'));
        static::assertSame('SERIAL', TypeMapper::mapType('increments', 'postgresql'));

        // SQLite
        static::assertSame('INTEGER', TypeMapper::mapType('bigIncrements', 'sqlite'));
        static::assertSame('INTEGER', TypeMapper::mapType('increments', 'sqlite'));
    }

    public function testCanMapSpecialTypes(): void
    {
        // IP Address
        static::assertSame('VARCHAR(45)', TypeMapper::mapType('ipAddress', 'mysql'));
        static::assertSame('INET', TypeMapper::mapType('ipAddress', 'postgresql'));
        static::assertSame('TEXT', TypeMapper::mapType('ipAddress', 'sqlite'));

        // MAC Address
        static::assertSame('VARCHAR(17)', TypeMapper::mapType('macAddress', 'mysql'));
        static::assertSame('MACADDR', TypeMapper::mapType('macAddress', 'postgresql'));
        static::assertSame('TEXT', TypeMapper::mapType('macAddress', 'sqlite'));

        // UUID
        static::assertSame('CHAR(36)', TypeMapper::mapType('uuid', 'mysql'));
        static::assertSame('UUID', TypeMapper::mapType('uuid', 'postgresql'));
        static::assertSame('TEXT', TypeMapper::mapType('uuid', 'sqlite'));
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

        static::assertSame('VARCHAR', $stringCompatibility['mysql']);
        static::assertSame('VARCHAR', $stringCompatibility['postgresql']);
        static::assertSame('TEXT', $stringCompatibility['sqlite']);
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
        static::assertSame('BIGINT UNSIGNED', $morphs[0]);
        static::assertSame('VARCHAR(255)', $morphs[1]);

        // timestamps devuelve array para created_at y updated_at
        $timestamps = TypeMapper::mapType('timestamps', 'mysql');
        static::assertIsArray($timestamps);
        static::assertCount(2, $timestamps);
        static::assertSame('TIMESTAMP', $timestamps[0]);
        static::assertSame('TIMESTAMP', $timestamps[1]);
    }
}
