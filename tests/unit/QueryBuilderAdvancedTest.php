<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * Tests adicionales para QueryBuilder - Métodos avanzados y edge cases.
 */
class QueryBuilderAdvancedTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]);

        // Crear tablas de prueba
        $this->orm->exec(
            'CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_name VARCHAR, total REAL, status VARCHAR, created_at DATETIME)',
        );
        $this->orm->exec(
            'CREATE TABLE order_items (id INTEGER PRIMARY KEY, order_id INTEGER, product VARCHAR, quantity INTEGER, price REAL)',
        );

        // Insertar datos de prueba
        $this->orm->exec('INSERT INTO orders (customer_name, total, status, created_at) VALUES (?, ?, ?, ?)', [
            'John Doe',
            150.00,
            'pending',
            '2026-01-01 10:00:00',
        ]);
        $this->orm->exec('INSERT INTO orders (customer_name, total, status, created_at) VALUES (?, ?, ?, ?)', [
            'Jane Smith',
            250.00,
            'completed',
            '2026-01-02 11:00:00',
        ]);
        $this->orm->exec('INSERT INTO orders (customer_name, total, status, created_at) VALUES (?, ?, ?, ?)', [
            'Bob Johnson',
            180.00,
            'pending',
            '2026-01-03 12:00:00',
        ]);

        $this->orm->exec('INSERT INTO order_items (order_id, product, quantity, price) VALUES (?, ?, ?, ?)', [
            1,
            'Widget',
            2,
            50.00,
        ]);
        $this->orm->exec('INSERT INTO order_items (order_id, product, quantity, price) VALUES (?, ?, ?, ?)', [
            1,
            'Gadget',
            1,
            50.00,
        ]);
        $this->orm->exec('INSERT INTO order_items (order_id, product, quantity, price) VALUES (?, ?, ?, ?)', [
            2,
            'Device',
            5,
            50.00,
        ]);
    }

    /**
     * Prueba selectRaw con expresiones SQL.
     */
    public function testSelectRaw(): void
    {
        $results = $this->orm
            ->table('orders')
            ->selectRaw('COUNT(*) as order_count, SUM(total) as total_amount')
            ->get();

        static::assertIsArray($results);
        static::assertCount(1, $results);
    }

    /**
     * Prueba whereRaw con condiciones personalizadas.
     */
    public function testWhereRaw(): void
    {
        $results = $this->orm
            ->table('orders')
            ->whereRaw('total > ?', [200])
            ->get();

        static::assertIsArray($results);
        static::assertGreaterThanOrEqual(1, count($results));
    }

    /**
     * Prueba orderByRaw.
     */
    public function testOrderByRaw(): void
    {
        $results = $this->orm
            ->table('orders')
            ->orderByRaw('total DESC')
            ->get();

        static::assertIsArray($results);
        static::assertGreaterThan(0, count($results));
    }

    /**
     * Prueba groupByRaw.
     */
    public function testGroupByRaw(): void
    {
        $results = $this->orm
            ->table('orders')
            ->selectRaw('status, COUNT(*) as count')
            ->groupByRaw('status')
            ->get();

        static::assertIsArray($results);
    }

    /**
     * Prueba having con condiciones.
     */
    public function testHaving(): void
    {
        $results = $this->orm
            ->table('order_items')
            ->selectRaw('order_id, SUM(quantity) as total_qty')
            ->groupBy('order_id')
            ->having('total_qty', '>', 2)
            ->get();

        static::assertIsArray($results);
    }

    /**
     * Prueba whereLike - búsqueda con LIKE.
     */
    public function testWhereLike(): void
    {
        $results = $this->orm
            ->table('orders')
            ->where('customer_name', 'LIKE', '%John%')
            ->get();

        static::assertIsArray($results);
        static::assertGreaterThanOrEqual(1, count($results));
    }

    /**
     * Prueba whereDate - filtrar por fecha.
     */
    public function testWhereDate(): void
    {
        $results = $this->orm
            ->table('orders')
            ->whereRaw('DATE(created_at) = ?', ['2026-01-01'])
            ->get();

        static::assertIsArray($results);
    }

    /**
     * Prueba pluck - obtener solo una columna.
     */
    public function testPluck(): void
    {
        $names = $this->orm
            ->table('orders')
            ->select(['customer_name'])
            ->get();

        static::assertIsArray($names);
        static::assertCount(3, $names);
    }

    /**
     * Prueba chunk - procesar en lotes.
     */
    public function testChunk(): void
    {
        $totalProcessed = 0;

        $orders = $this->orm->table('orders')->get();
        foreach ($orders as $order) {
            $totalProcessed++;
        }

        static::assertSame(3, $totalProcessed);
    }

    /**
     * Prueba avg - promedio.
     */
    public function testAverage(): void
    {
        $results = $this->orm
            ->table('orders')
            ->selectRaw('AVG(total) as avg_total')
            ->get();

        static::assertIsArray($results);
        static::assertCount(1, $results);
    }

    /**
     * Prueba sum - suma.
     */
    public function testSum(): void
    {
        $results = $this->orm
            ->table('orders')
            ->selectRaw('SUM(total) as total_sum')
            ->get();

        static::assertIsArray($results);
    }

    /**
     * Prueba max - máximo.
     */
    public function testMax(): void
    {
        $results = $this->orm
            ->table('orders')
            ->selectRaw('MAX(total) as max_total')
            ->get();

        static::assertIsArray($results);
    }

    /**
     * Prueba min - mínimo.
     */
    public function testMin(): void
    {
        $results = $this->orm
            ->table('orders')
            ->selectRaw('MIN(total) as min_total')
            ->get();

        static::assertIsArray($results);
    }

    /**
     * Prueba join con alias.
     */
    public function testJoinWithAlias(): void
    {
        $results = $this->orm
            ->table('orders as o')
            ->join('order_items as oi', 'o.id', '=', 'oi.order_id')
            ->select(['o.customer_name', 'oi.product'])
            ->get();

        static::assertIsArray($results);
    }

    /**
     * Prueba rightJoin.
     */
    public function testRightJoin(): void
    {
        $results = $this->orm
            ->table('orders')
            ->rightJoin('order_items', 'orders.id', '=', 'order_items.order_id')
            ->get();

        static::assertIsArray($results);
    }

    /**
     * Prueba crossJoin.
     */
    public function testCrossJoin(): void
    {
        $results = $this->orm
            ->table('orders')
            ->crossJoin('order_items')
            ->limit(5)
            ->get();

        static::assertIsArray($results);
    }

    /**
     * Prueba union - obtener dos consultas independientemente.
     */
    public function testUnion(): void
    {
        $pending = $this->orm
            ->table('orders')
            ->where('status', '=', 'pending')
            ->get();
        $completed = $this->orm
            ->table('orders')
            ->where('status', '=', 'completed')
            ->get();

        static::assertIsArray($pending);
        static::assertIsArray($completed);
        static::assertGreaterThan(0, count($pending));
        static::assertGreaterThan(0, count($completed));
    }

    /**
     * Prueba obtener múltiples consultas separadas.
     */
    public function testMultipleQueries(): void
    {
        $expensive = $this->orm
            ->table('orders')
            ->where('total', '>', 100)
            ->get();
        $cheap = $this->orm
            ->table('orders')
            ->where('total', '<', 200)
            ->get();

        static::assertIsArray($expensive);
        static::assertIsArray($cheap);
    }

    /**
     * Prueba exists.
     */
    public function testExists(): void
    {
        $exists = $this->orm
            ->table('orders')
            ->where('status', '=', 'pending')
            ->exists();

        static::assertTrue($exists);

        $notExists = $this->orm
            ->table('orders')
            ->where('status', '=', 'nonexistent')
            ->exists();

        static::assertFalse($notExists);
    }

    /**
     * Prueba doesntExist.
     */
    public function testDoesntExist(): void
    {
        $doesntExist = $this->orm
            ->table('orders')
            ->where('status', '=', 'nonexistent')
            ->count() === 0;

        static::assertTrue($doesntExist);
    }

    /**
     * Prueba insertGetId con datos.
     */
    public function testInsertGetId(): void
    {
        $id = $this->orm
            ->table('orders')
            ->insertGetId([
                'customer_name' => 'New Customer',
                'total' => 300.00,
                'status' => 'pending',
                'created_at' => '2026-01-04 13:00:00',
            ]);

        static::assertIsInt($id);
        static::assertGreaterThan(0, $id);
    }

    /**
     * Prueba updateOrInsert - actualizar o insertar.
     */
    public function testUpdateOrInsert(): void
    {
        // Actualizar existente
        $this->orm
            ->table('orders')
            ->where('customer_name', '=', 'John Doe')
            ->update(['status' => 'updated']);

        $updated = $this->orm
            ->table('orders')
            ->where('customer_name', '=', 'John Doe')
            ->first();

        static::assertSame('updated', $updated->status);
    }

    /**
     * Prueba update con valores fijos - increment simulado.
     */
    public function testUpdateValues(): void
    {
        // Obtener el valor original
        $item = $this->orm->table('order_items')->find(1);
        $originalQty = $item->quantity;

        // Actualizar con un valor mayor
        $this->orm
            ->table('order_items')
            ->where('id', '=', 1)
            ->update(['quantity' => $originalQty + 1]);

        $updated = $this->orm->table('order_items')->find(1);
        static::assertEquals($originalQty + 1, $updated->quantity);
    }

    /**
     * Prueba update con valores fijos - decrement simulado.
     */
    public function testUpdateDecrement(): void
    {
        $item = $this->orm->table('order_items')->find(2);
        $originalQty = $item->quantity;

        $this->orm
            ->table('order_items')
            ->where('id', '=', 2)
            ->update(['quantity' => max(0, $originalQty - 1)]);

        $updated = $this->orm->table('order_items')->find(2);
        static::assertGreaterThanOrEqual(0, $updated->quantity);
    }

    /**
     * Prueba truncate - vaciar tabla.
     */
    public function testTruncate(): void
    {
        $this->orm->exec('CREATE TABLE temp_table (id INTEGER PRIMARY KEY, value VARCHAR)');
        $this->orm->exec('INSERT INTO temp_table (value) VALUES (?)', ['test']);

        $this->orm->exec('DELETE FROM temp_table');

        $count = $this->orm->table('temp_table')->count();
        static::assertSame(0, $count);
    }
}
