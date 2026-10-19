<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

/**
 * @group postgresql
 */
class SchemaSearchPathTest extends TestCase
{
    protected function tearDown(): void
    {
        self::$orm->exec('DROP SCHEMA IF EXISTS otro_esquema CASCADE');
        self::$orm->exec('DROP TABLE IF EXISTS mismo_nombre');
        parent::tearDown();
    }

    public function testConDosEsquemasSoloVeLasColumnasDeLaTablaVisibleYEnSuOrden(): void
    {
        self::$orm->exec('CREATE SCHEMA otro_esquema');
        self::$orm->exec('CREATE TABLE otro_esquema.mismo_nombre (ajena TEXT, id INTEGER)');
        self::$orm->exec('CREATE TABLE mismo_nombre (id INTEGER, zeta TEXT, alfa TEXT)');

        $columnas = array_column(self::$orm->schema('columns', 'mismo_nombre'), 'name');

        self::assertSame(['id', 'zeta', 'alfa'], $columnas);
    }
}
