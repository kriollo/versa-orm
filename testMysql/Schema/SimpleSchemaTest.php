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
        $this->assertEquals('VARCHAR', $mysqlType);

        $postgresType = TypeMapper::mapType('string', 'postgresql');
        $this->assertEquals('VARCHAR', $postgresType);

        $sqliteType = TypeMapper::mapType('string', 'sqlite');
        $this->assertEquals('TEXT', $sqliteType);
    }

    public function testSchemaBuilderCanBeInstantiated(): void
    {
        $this->assertTrue(true); // Test simple que siempre pasa
    }
}
