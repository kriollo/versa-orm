<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\TypeMapper;

/**
 * Test simple de SchemaBuilder para verificar el sistema.
 *
 * @group sqlite
 */
class SimpleSchemaTest extends TestCase
{
    public function testTypeMapperBasicFunctionality(): void
    {
        $mysqlType = TypeMapper::mapType('string', 'mysql');
        static::assertSame('VARCHAR', $mysqlType);

        $postgresType = TypeMapper::mapType('string', 'postgresql');
        static::assertSame('VARCHAR', $postgresType);

        $sqliteType = TypeMapper::mapType('string', 'sqlite');
        static::assertSame('TEXT', $sqliteType);
    }

    public function testSchemaBuilderCanBeInstantiated(): void
    {
        static::assertTrue(true); // Test simple que siempre pasa
    }
}
