<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use Throwable;
use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

/**
 * Tests para la creación de encabezados de factura con detalles en JSON y concatenación de fechas en SQLite.
 */
class SQLiteInvoiceJsonTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        VersaModel::setORM(self::$orm);
        $this->createInvoiceTestTables();
    }

    protected function tearDown(): void
    {
        try {
            self::$orm->schemaDrop('factura_items');
            self::$orm->schemaDrop('facturas');
            self::$orm->schemaDrop('empresas');
        } catch (Throwable $e) {
            // Ignorar si las tablas no existen
        }
        parent::tearDown();
    }

    private function createInvoiceTestTables(): void
    {
        // Crear tabla de empresas
        self::$orm->schemaCreate('empresas', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'nombre', 'type' => 'VARCHAR(255)', 'nullable' => false],
        ]);

        // Crear tabla de facturas
        self::$orm->schemaCreate('facturas', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'id_empresa', 'type' => 'INTEGER', 'nullable' => true],
            ['name' => 'numero', 'type' => 'VARCHAR(20)', 'nullable' => false],
            ['name' => 'cliente', 'type' => 'VARCHAR(255)', 'nullable' => false],
            ['name' => 'anno', 'type' => 'INTEGER'],
            ['name' => 'mes', 'type' => 'INTEGER'],
        ]);

        // Crear tabla de items de factura
        self::$orm->schemaCreate('factura_items', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'id_factura', 'type' => 'INTEGER', 'nullable' => false],
            ['name' => 'tipo', 'type' => 'VARCHAR(50)'],
            ['name' => 'descripcion', 'type' => 'TEXT'],
            ['name' => 'cantidad', 'type' => 'DECIMAL(10,2)'],
            ['name' => 'precio_unitario', 'type' => 'DECIMAL(10,2)'],
            ['name' => 'subtotal', 'type' => 'DECIMAL(10,2)'],
            ['name' => 'detalles', 'type' => 'JSON'],
        ]);

        // Insertar datos de prueba
        $empresaId = self::$orm
            ->table('empresas')
            ->insertGetId([
                'nombre' => 'Empresa 1',
            ]);

        $facturaId = self::$orm
            ->table('facturas')
            ->insertGetId([
                'id_empresa' => $empresaId,
                'numero' => 'F-001',
                'cliente' => 'Cliente 1',
                'anno' => 2024,
                'mes' => 2,
            ]);

        self::$orm
            ->table('factura_items')
            ->insert([
                'id_factura' => $facturaId,
                'tipo' => 'Servicio',
                'descripcion' => 'Desarrollo Web',
                'cantidad' => 1,
                'precio_unitario' => 1000.00,
                'subtotal' => 1000.00,
                'detalles' => json_encode(['horas' => 10, 'tarifa' => 100]),
            ]);

        self::$orm
            ->table('factura_items')
            ->insert([
                'id_factura' => $facturaId,
                'tipo' => 'Producto',
                'descripcion' => 'Licencia Anual',
                'cantidad' => 2,
                'precio_unitario' => 500.00,
                'subtotal' => 1000.00,
                'detalles' => json_encode(['renovable' => true]),
            ]);
    }

    public function test_invoice_header_with_items_json(): void
    {
        $qb = new QueryBuilder(self::$orm, 'facturas');

        // En SQLite usamos json_group_array y json_object
        $qb
            ->lazy()
            ->select(['facturas.id', 'facturas.numero', 'facturas.cliente'])
            ->selectRaw('COUNT(*) OVER() AS total_count');

        // Agregar items como JSON
        $qb->selectRaw(
            '(SELECT json_group_array(json_object(\'id\',fi.id,\'tipo\',fi.tipo,\'descripcion\',fi.descripcion,\'cantidad\',fi.cantidad,\'precio_unitario\',fi.precio_unitario,\'subtotal\',fi.subtotal,\'detalles\',json(fi.detalles))) FROM factura_items fi WHERE fi.id_factura=facturas.id) AS items',
        );

        $qb->leftJoin('empresas', 'facturas.id_empresa', '=', 'empresas.id');

        $qb->orderByRaw('facturas.id ASC')->limit(10)->offset(0);
        $result = $qb->collect();

        static::assertNotEmpty($result);
        static::assertArrayHasKey('items', $result[0]);

        $items = $result[0]['items'];
        static::assertIsArray($items);
        static::assertCount(2, $items);
        static::assertSame('Servicio', $items[0]['tipo']);
        static::assertSame('Producto', $items[1]['tipo']);
    }

    public function test_date_concatenation_with_operator(): void
    {
        $qb = new QueryBuilder(self::$orm, 'facturas');

        // Usando el operador || de SQLite
        $qb->select(['id', 'numero'])->selectRaw("anno || '/' || mes AS fecha_formateada");

        $result = $qb->get();

        static::assertNotEmpty($result);
        static::assertSame('2024/2', $result[0]['fecha_formateada']);
    }

    public function test_date_concatenation_with_pipe(): void
    {
        $qb = new QueryBuilder(self::$orm, 'facturas');

        // Usando | como separador
        $qb->select(['id', 'numero'])->selectRaw("anno || '|' || mes AS fecha_formateada");

        $result = $qb->get();

        static::assertNotEmpty($result);
        static::assertSame('2024|2', $result[0]['fecha_formateada']);
    }

    public function test_sql_export(): void
    {
        $qb = new QueryBuilder(self::$orm, 'facturas');
        $qb->select(['id', 'numero'])->where('anno', '=', 2024)->where('mes', '>', 1);

        $sql = $qb->toSql();
        $bindings = $qb->getBindings();

        static::assertStringContainsString('SELECT id, numero FROM facturas WHERE anno = ? AND mes > ?', $sql);
        static::assertCount(2, $bindings);
        static::assertSame(2024, $bindings[0]);
        static::assertSame(1, $bindings[1]);
    }
}
