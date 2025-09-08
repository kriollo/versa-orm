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
        $this->assertEquals('VARCHAR', TypeMapper::mapType('string', 'mysql'));
        $this->assertEquals('INT', TypeMapper::mapType('integer', 'mysql'));
        $this->assertEquals('BIGINT', TypeMapper::mapType('bigInteger', 'mysql'));
        $this->assertEquals('TEXT', TypeMapper::mapType('text', 'mysql'));
        $this->assertEquals('TINYINT(1)', TypeMapper::mapType('boolean', 'mysql'));
        $this->assertEquals('JSON', TypeMapper::mapType('json', 'mysql'));

        // PostgreSQL
        $this->assertEquals('VARCHAR', TypeMapper::mapType('string', 'postgresql'));
        $this->assertEquals('INTEGER', TypeMapper::mapType('integer', 'postgresql'));
        $this->assertEquals('BIGINT', TypeMapper::mapType('bigInteger', 'postgresql'));
        $this->assertEquals('TEXT', TypeMapper::mapType('text', 'postgresql'));
        $this->assertEquals('BOOLEAN', TypeMapper::mapType('boolean', 'postgresql'));
        $this->assertEquals('JSON', TypeMapper::mapType('json', 'postgresql'));

        // SQLite
        $this->assertEquals('TEXT', TypeMapper::mapType('string', 'sqlite'));
        $this->assertEquals('INTEGER', TypeMapper::mapType('integer', 'sqlite'));
        $this->assertEquals('INTEGER', TypeMapper::mapType('bigInteger', 'sqlite'));
        $this->assertEquals('TEXT', TypeMapper::mapType('text', 'sqlite'));
        $this->assertEquals('INTEGER', TypeMapper::mapType('boolean', 'sqlite'));
        $this->assertEquals('TEXT', TypeMapper::mapType('json', 'sqlite'));
    }

    public function testCanMapTypesWithOptions(): void
    {
        // String con longitud
        $this->assertEquals('VARCHAR(100)', TypeMapper::mapType('string', 'mysql', ['length' => 100]));
        $this->assertEquals('VARCHAR(100)', TypeMapper::mapType('string', 'postgresql', ['length' => 100]));
        $this->assertEquals('TEXT', TypeMapper::mapType('string', 'sqlite', ['length' => 100]));

        // Decimal con precisión
        $this->assertEquals('DECIMAL(10,2)', TypeMapper::mapType('decimal', 'mysql', [
            'precision' => 10,
            'scale' => 2,
        ]));
        $this->assertEquals('DECIMAL(10,2)', TypeMapper::mapType('decimal', 'postgresql', [
            'precision' => 10,
            'scale' => 2,
        ]));
        $this->assertEquals('NUMERIC(10,2)', TypeMapper::mapType('decimal', 'sqlite', [
            'precision' => 10,
            'scale' => 2,
        ]));
    }

    public function testCanMapEnumTypes(): void
    {
        $values = ['active', 'inactive', 'pending'];

        // MySQL soporta ENUM nativo
        $mysqlEnum = TypeMapper::mapType('enum', 'mysql', ['values' => $values]);
        $this->assertEquals("ENUM('active','inactive','pending')", $mysqlEnum);

        // PostgreSQL y SQLite usan VARCHAR/TEXT
        $this->assertEquals('VARCHAR(255)', TypeMapper::mapType('enum', 'postgresql', ['values' => $values]));
        $this->assertEquals('TEXT', TypeMapper::mapType('enum', 'sqlite', ['values' => $values]));
    }

    public function testCanMapSetTypes(): void
    {
        $values = ['read', 'write', 'execute'];

        // MySQL soporta SET nativo
        $mysqlSet = TypeMapper::mapType('set', 'mysql', ['values' => $values]);
        $this->assertEquals("SET('read','write','execute')", $mysqlSet);

        // PostgreSQL y SQLite usan TEXT
        $this->assertEquals('TEXT', TypeMapper::mapType('set', 'postgresql', ['values' => $values]));
        $this->assertEquals('TEXT', TypeMapper::mapType('set', 'sqlite', ['values' => $values]));
    }

    public function testCanMapIncrementTypes(): void
    {
        // MySQL
        $this->assertEquals('BIGINT UNSIGNED', TypeMapper::mapType('bigIncrements', 'mysql'));
        $this->assertEquals('INT UNSIGNED', TypeMapper::mapType('increments', 'mysql'));

        // PostgreSQL
        $this->assertEquals('BIGSERIAL', TypeMapper::mapType('bigIncrements', 'postgresql'));
        $this->assertEquals('SERIAL', TypeMapper::mapType('increments', 'postgresql'));

        // SQLite
        $this->assertEquals('INTEGER', TypeMapper::mapType('bigIncrements', 'sqlite'));
        $this->assertEquals('INTEGER', TypeMapper::mapType('increments', 'sqlite'));
    }

    public function testCanMapSpecialTypes(): void
    {
        // IP Address
        $this->assertEquals('VARCHAR(45)', TypeMapper::mapType('ipAddress', 'mysql'));
        $this->assertEquals('INET', TypeMapper::mapType('ipAddress', 'postgresql'));
        $this->assertEquals('TEXT', TypeMapper::mapType('ipAddress', 'sqlite'));

        // MAC Address
        $this->assertEquals('VARCHAR(17)', TypeMapper::mapType('macAddress', 'mysql'));
        $this->assertEquals('MACADDR', TypeMapper::mapType('macAddress', 'postgresql'));
        $this->assertEquals('TEXT', TypeMapper::mapType('macAddress', 'sqlite'));

        // UUID
        $this->assertEquals('CHAR(36)', TypeMapper::mapType('uuid', 'mysql'));
        $this->assertEquals('UUID', TypeMapper::mapType('uuid', 'postgresql'));
        $this->assertEquals('TEXT', TypeMapper::mapType('uuid', 'sqlite'));
    }

    public function testCanGetSupportedTypes(): void
    {
        $mysqlTypes = TypeMapper::getSupportedTypes('mysql');
        $postgresTypes = TypeMapper::getSupportedTypes('postgresql');
        $sqliteTypes = TypeMapper::getSupportedTypes('sqlite');

        $this->assertIsArray($mysqlTypes);
        $this->assertIsArray($postgresTypes);
        $this->assertIsArray($sqliteTypes);

        $this->assertContains('string', $mysqlTypes);
        $this->assertContains('integer', $mysqlTypes);
        $this->assertContains('boolean', $mysqlTypes);

        $this->assertContains('string', $postgresTypes);
        $this->assertContains('integer', $postgresTypes);
        $this->assertContains('boolean', $postgresTypes);

        $this->assertContains('string', $sqliteTypes);
        $this->assertContains('integer', $sqliteTypes);
        $this->assertContains('boolean', $sqliteTypes);
    }

    public function testCanCheckTypeSupport(): void
    {
        $this->assertTrue(TypeMapper::isTypeSupported('string', 'mysql'));
        $this->assertTrue(TypeMapper::isTypeSupported('integer', 'postgresql'));
        $this->assertTrue(TypeMapper::isTypeSupported('boolean', 'sqlite'));

        $this->assertFalse(TypeMapper::isTypeSupported('nonexistent', 'mysql'));
        $this->assertFalse(TypeMapper::isTypeSupported('string', 'nonexistent'));
    }

    public function testCanGetTypeCompatibility(): void
    {
        $stringCompatibility = TypeMapper::getTypeCompatibility('string');

        $this->assertIsArray($stringCompatibility);
        $this->assertArrayHasKey('mysql', $stringCompatibility);
        $this->assertArrayHasKey('postgresql', $stringCompatibility);
        $this->assertArrayHasKey('sqlite', $stringCompatibility);

        $this->assertEquals('VARCHAR', $stringCompatibility['mysql']);
        $this->assertEquals('VARCHAR', $stringCompatibility['postgresql']);
        $this->assertEquals('TEXT', $stringCompatibility['sqlite']);
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
        $this->assertIsArray($morphs);
        $this->assertCount(2, $morphs);
        $this->assertEquals('BIGINT UNSIGNED', $morphs[0]);
        $this->assertEquals('VARCHAR(255)', $morphs[1]);

        // timestamps devuelve array para created_at y updated_at
        $timestamps = TypeMapper::mapType('timestamps', 'mysql');
        $this->assertIsArray($timestamps);
        $this->assertCount(2, $timestamps);
        $this->assertEquals('TIMESTAMP', $timestamps[0]);
        $this->assertEquals('TIMESTAMP', $timestamps[1]);
    }
}
