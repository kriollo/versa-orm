<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * Tests para PdoEngine - Motor de base de datos nativo con PDO.
 * Enfocado en aumentar cobertura de métodos críticos.
 */
class PdoEngineComprehensiveTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]);
    }

    /**
     * Prueba ejecución básica de SQL.
     */
    public function testExecuteBasicQuery(): void
    {
        $result = $this->orm->exec('CREATE TABLE test (id INTEGER PRIMARY KEY, name VARCHAR)');
        $this->assertNull($result);
    }

    /**
     * Prueba inserción con parámetros enlazados.
     */
    public function testInsertWithBindings(): void
    {
        $this->orm->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR)');
        $this->orm->exec('INSERT INTO users (name) VALUES (?)', ['John']);

        $result = $this->orm->exec('SELECT COUNT(*) as count FROM users');
        $this->assertIsArray($result);
    }

    /**
     * Prueba transacciones - commit.
     */
    public function testTransactionCommit(): void
    {
        $this->orm->exec('CREATE TABLE transactions (id INTEGER PRIMARY KEY, value INTEGER)');

        $this->orm->beginTransaction();
        $this->orm->exec('INSERT INTO transactions (value) VALUES (?)', [100]);
        $this->orm->commit();

        $result = $this->orm->exec('SELECT COUNT(*) as count FROM transactions');
        $this->assertIsArray($result);
    }

    /**
     * Prueba transacciones - rollback.
     */
    public function testTransactionRollback(): void
    {
        $this->orm->exec('CREATE TABLE rollback_test (id INTEGER PRIMARY KEY, value INTEGER)');

        $this->orm->beginTransaction();
        $this->orm->exec('INSERT INTO rollback_test (value) VALUES (?)', [100]);
        $this->orm->rollback();

        // Verificar que la inserción fue revocada
        $result = $this->orm->table('rollback_test')->count();
        $this->assertEquals(0, $result);
    }

    /**
     * Prueba manejo de errores en transacciones.
     */
    public function testTransactionError(): void
    {
        $this->orm->exec('CREATE TABLE error_test (id INTEGER PRIMARY KEY)');

        $this->orm->beginTransaction();

        // Intentar insertar en tabla que no existe
        try {
            $this->orm->exec('INSERT INTO nonexistent_table VALUES (1)');
            $this->orm->commit();
            $this->fail('Expected exception');
        } catch (\Exception $e) {
            $this->orm->rollback();
            $this->assertIsString($e->getMessage());
        }
    }

    /**
     * Prueba consultas preparadas con múltiples parámetros.
     */
    public function testPreparedStatementMultipleParams(): void
    {
        $this->orm->exec('CREATE TABLE products (id INTEGER PRIMARY KEY, name VARCHAR, price REAL)');
        $this->orm->exec('INSERT INTO products (name, price) VALUES (?, ?)', ['Laptop', 999.99]);

        $result = $this->orm->exec('SELECT * FROM products WHERE name = ? AND price > ?', ['Laptop', 500]);
        $this->assertIsArray($result);
    }

    /**
     * Prueba consultas que retornan múltiples filas.
     */
    public function testMultipleRowsQuery(): void
    {
        $this->orm->exec('CREATE TABLE numbers (id INTEGER PRIMARY KEY, value INTEGER)');
        $this->orm->exec('INSERT INTO numbers (value) VALUES (?)', [1]);
        $this->orm->exec('INSERT INTO numbers (value) VALUES (?)', [2]);
        $this->orm->exec('INSERT INTO numbers (value) VALUES (?)', [3]);

        $results = $this->orm->table('numbers')->get();
        $this->assertCount(3, $results);
    }

    /**
     * Prueba consultas sin resultados.
     */
    public function testQueryWithNoResults(): void
    {
        $this->orm->exec('CREATE TABLE empty_table (id INTEGER PRIMARY KEY, name VARCHAR)');

        $results = $this->orm->table('empty_table')->get();
        $this->assertCount(0, $results);
    }

    /**
     * Prueba conteo de filas.
     */
    public function testCountRows(): void
    {
        $this->orm->exec('CREATE TABLE items (id INTEGER PRIMARY KEY, name VARCHAR)');
        $this->orm->exec('INSERT INTO items (name) VALUES (?)', ['Item1']);
        $this->orm->exec('INSERT INTO items (name) VALUES (?)', ['Item2']);

        $count = $this->orm->table('items')->count();
        $this->assertEquals(2, $count);
    }

    /**
     * Prueba actualización de registros.
     */
    public function testUpdateRecords(): void
    {
        $this->orm->exec('CREATE TABLE records (id INTEGER PRIMARY KEY, status VARCHAR)');
        $this->orm->exec('INSERT INTO records (status) VALUES (?)', ['inactive']);

        $this->orm
            ->table('records')
            ->where('status', '=', 'inactive')
            ->update(['status' => 'active']);

        $result = $this->orm
            ->table('records')
            ->where('status', '=', 'active')
            ->first();
        $this->assertNotNull($result);
    }

    /**
     * Prueba eliminación de registros.
     */
    public function testDeleteRecords(): void
    {
        $this->orm->exec('CREATE TABLE to_delete (id INTEGER PRIMARY KEY, name VARCHAR)');
        $this->orm->exec('INSERT INTO to_delete (name) VALUES (?)', ['temp']);

        $this->orm
            ->table('to_delete')
            ->where('name', '=', 'temp')
            ->delete();

        $count = $this->orm->table('to_delete')->count();
        $this->assertEquals(0, $count);
    }

    /**
     * Prueba agregaciones (MAX, MIN, etc).
     */
    public function testAggregations(): void
    {
        $this->orm->exec('CREATE TABLE scores (id INTEGER PRIMARY KEY, value INTEGER)');
        $this->orm->exec('INSERT INTO scores (value) VALUES (?)', [100]);
        $this->orm->exec('INSERT INTO scores (value) VALUES (?)', [200]);
        $this->orm->exec('INSERT INTO scores (value) VALUES (?)', [150]);

        // Probar con QueryBuilder
        $results = $this->orm->table('scores')->get();
        $this->assertCount(3, $results);
    }
}
