<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaORM;

/**
 * @group sqlite
 */
class SchemaStoreTest extends TestCase
{
    /** @var array<string, array<array-key, mixed>> */
    private array $store = [];

    protected function setUp(): void
    {
        $this->store = [];
        $this->registrar();
        self::$orm->exec('CREATE TABLE IF NOT EXISTS schema_store_x (id INTEGER PRIMARY KEY, nombre TEXT)');
    }

    protected function tearDown(): void
    {
        VersaORM::schemaCache(null);
        VersaORM::onQuery(null);
        self::$orm->exec('DROP TABLE IF EXISTS schema_store_x');
        parent::tearDown();
    }

    public function testGuardaLaIntrospeccionYLaSiguientePeticionNoConsultaLaBase(): void
    {
        $columnas = self::$orm->schema('columns', 'schema_store_x');
        self::assertCount(1, $this->store);
        self::assertSame($columnas, array_values($this->store)[0]);

        // Otra petición: la memoria del proceso está vacía, el almacén no
        $this->vaciarMemoriaSinTocarElAlmacen();
        $clave = array_key_first($this->store);
        $this->store[$clave] = [['name' => 'desde_el_almacen']];

        $consultas = 0;
        VersaORM::onQuery(static function () use (&$consultas): void {
            $consultas++;
        });

        self::assertSame([['name' => 'desde_el_almacen']], self::$orm->schema('columns', 'schema_store_x'));
        self::assertSame(0, $consultas);
    }

    public function testUnDdlVaciaElAlmacen(): void
    {
        self::$orm->schema('columns', 'schema_store_x');
        self::assertNotEmpty($this->store);

        self::$orm->exec('ALTER TABLE schema_store_x ADD COLUMN extra TEXT');

        self::assertSame([], $this->store);
        $nombres = array_column(self::$orm->schema('columns', 'schema_store_x'), 'name');
        self::assertContains('extra', $nombres);
    }

    public function testRevertirUnaTransaccionConDdlVaciaElAlmacenYUnaSinDdlNo(): void
    {
        self::$orm->beginTransaction();
        self::$orm->exec('ALTER TABLE schema_store_x ADD COLUMN temporal TEXT');
        self::$orm->schema('columns', 'schema_store_x');
        self::assertNotEmpty($this->store, 'se guardó el esquema con la columna que se va a revertir');
        self::$orm->rollBack();

        self::assertSame([], $this->store);
        self::assertNotContains('temporal', array_column(self::$orm->schema('columns', 'schema_store_x'), 'name'));

        self::$orm->beginTransaction();
        self::$orm->exec("INSERT INTO schema_store_x (nombre) VALUES ('x')");
        self::$orm->rollBack();
        self::assertNotEmpty($this->store, 'un rollback sin DDL no toca el esquema guardado');
    }

    public function testSinAlmacenNoGuardaNada(): void
    {
        VersaORM::schemaCache(null);
        self::$orm->exec('ALTER TABLE schema_store_x ADD COLUMN otra TEXT');

        self::$orm->schema('columns', 'schema_store_x');

        self::assertSame([], $this->store);
    }

    private function registrar(): void
    {
        VersaORM::schemaCache(
            get: fn(string $clave): ?array => $this->store[$clave] ?? null,
            set: function (string $clave, array $valor): void {
                $this->store[$clave] = $valor;
            },
            clear: function (): void {
                $this->store = [];
            },
        );
    }

    private function vaciarMemoriaSinTocarElAlmacen(): void
    {
        VersaORM::schemaCache(null);
        self::$orm->exec('CREATE TABLE IF NOT EXISTS schema_store_tmp (id INTEGER)');
        self::$orm->exec('DROP TABLE schema_store_tmp');
        $this->registrar();
    }
}
