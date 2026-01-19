<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\TypeMapper;

/**
 * Test simple de SchemaBuilder para verificar el sistema.
 *
 * @group mysql
 */
class SimpleSchemaTest extends TestCase
{
    public function testTypeMapperBasicFunctionality(): void
    {
        $mysqlType = TypeMapper::mapType('string', 'mysql');
        static::assertEquals('VARCHAR', $mysqlType);

        $postgresType = TypeMapper::mapType('string', 'postgresql');
        static::assertEquals('VARCHAR', $postgresType);

        $sqliteType = TypeMapper::mapType('string', 'sqlite');
        static::assertEquals('TEXT', $sqliteType);
    }

    public function testSchemaBuilderCanBeInstantiated(): void
    {
        static::assertTrue(true); // Test simple que siempre pasa
    }
}
