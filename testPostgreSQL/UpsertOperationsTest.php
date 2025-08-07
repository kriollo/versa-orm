<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaORMException;

/**
 * Test unitarios para operaciones UPSERT individuales.
 *
 * Cubre los métodos: upsert(), insertOrUpdate(), save(), createOrUpdate()
 * implementados en la Tarea 2.2 - Operaciones CRUD completas.
 */
class UpsertOperationsTest extends TestCase
{
    //======================================================================
    // TESTS PARA MÉTODO upsert()
    //======================================================================

    public function testUpsertNewRecord(): void
    {
        // Test: Insertar un nuevo producto usando upsert
        $productData = [
            'sku' => 'UPSERT-NEW-001',
            'name' => 'Nuevo Producto Upsert',
            'price' => 299.99,
            'stock' => 15
        ];

        $result = self::$orm->table('products')->upsert(
            $productData,
            ['sku'], // Clave única
            ['name', 'price', 'stock'] // Campos a actualizar si existe
        );

        $this->assertIsArray($result);
        $this->assertEquals('success', $result['status']);
        $this->assertEquals('inserted', $result['operation']);
        $this->assertEquals(1, $result['rows_affected']);

        // Verificar que se insertó correctamente
        $inserted = self::$orm->table('products')->where('sku', '=', 'UPSERT-NEW-001')->firstArray();
        $this->assertNotNull($inserted);
        $this->assertEquals('Nuevo Producto Upsert', $inserted['name']);
        $this->assertEquals(299.99, $inserted['price']);
    }

    public function testUpsertExistingRecord(): void
    {
        // Test: Actualizar un producto existente usando upsert
        $existingProduct = [
            'sku' => 'P001', // Ya existe en los datos de prueba
            'name' => 'Laptop Actualizada',
            'price' => 1299.99,
            'stock' => 25
        ];

        $result = self::$orm->table('products')->upsert(
            $existingProduct,
            ['sku'], // Clave única
            ['name', 'price', 'stock'] // Solo actualizar estos campos
        );

        $this->assertIsArray($result);
        $this->assertEquals('success', $result['status']);
        $this->assertEquals('updated', $result['operation']);
        $this->assertEquals(1, $result['rows_affected']);

        // Verificar que se actualizó correctamente
        $updated = self::$orm->table('products')->where('sku', '=', 'P001')->firstArray();
        $this->assertNotNull($updated);
        $this->assertEquals('Laptop Actualizada', $updated['name']);
        $this->assertEquals(1299.99, $updated['price']);
        $this->assertEquals(25, $updated['stock']);
    }

    public function testUpsertWithMultipleUniqueKeys(): void
    {
        // Test: Upsert con múltiples claves únicas
        $userData = [
            'name' => 'Test Usuario',
            'email' => 'alice@example.com', // Ya existe
            'status' => 'super_active'
        ];

        $result = self::$orm->table('users')->upsert(
            $userData,
            ['email'], // Clave única
            ['name', 'status'] // Campos a actualizar
        );

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('updated', $result['operation']);

        // Verificar actualización
        $updated = self::$orm->table('users')->where('email', '=', 'alice@example.com')->firstArray();
        $this->assertEquals('Test Usuario', $updated['name']);
        $this->assertEquals('super_active', $updated['status']);
    }

    public function testUpsertWithEmptyUniqueKeys(): void
    {
        // Test: Upsert debe fallar sin claves únicas
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsert requires unique keys');

        self::$orm->table('products')->upsert(
            ['sku' => 'TEST', 'name' => 'Test'],
            [], // Sin claves únicas - debe fallar
            ['name']
        );
    }

    public function testUpsertWithInvalidColumnNames(): void
    {
        // Test: Upsert debe validar nombres de columnas
        $this->expectException(VersaORMException::class);

        self::$orm->table('products')->upsert(
            ['sku' => 'TEST', 'name' => 'Test'],
            ['invalid--column'], // Nombre de columna inválido
            ['name']
        );
    }

    //======================================================================
    // TESTS PARA MÉTODO insertOrUpdate()
    //======================================================================

    public function testInsertOrUpdateNewRecord(): void
    {
        // Test: insertOrUpdate debe insertar un nuevo registro
        $userData = [
            'name' => 'New InsertOrUpdate User',
            'email' => 'insertupdate@example.com',
            'status' => 'active'
        ];

        $result = self::$orm->table('users')->insertOrUpdate(
            $userData,
            ['email']
        );

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('inserted', $result['operation']);

        // Verificar inserción
        $inserted = self::$orm->table('users')->where('email', '=', 'insertupdate@example.com')->firstArray();
        $this->assertNotNull($inserted);
        $this->assertEquals('New InsertOrUpdate User', $inserted['name']);
    }

    public function testInsertOrUpdateExistingRecord(): void
    {
        // Test: insertOrUpdate debe actualizar registro existente
        $updatedData = [
            'name' => 'Alice Updated',
            'email' => 'alice@example.com', // Ya existe
            'status' => 'updated'
        ];

        $result = self::$orm->table('users')->insertOrUpdate(
            $updatedData,
            ['email']
        );

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('updated', $result['operation']);

        // Verificar actualización
        $updated = self::$orm->table('users')->where('email', '=', 'alice@example.com')->firstArray();
        $this->assertEquals('Alice Updated', $updated['name']);
        $this->assertEquals('updated', $updated['status']);
    }

    //======================================================================
    // TESTS PARA MÉTODO save()
    //======================================================================

    public function testSaveNewRecord(): void
    {
        // Test: save() debe detectar registro nuevo e insertar
        $newUser = [
            'name' => 'Usuario Save',
            'email' => 'save@example.com',
            'status' => 'active'
        ];

        $result = self::$orm->table('users')->save($newUser); // Sin ID = inserción

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('inserted', $result['operation']);
        $this->assertIsNumeric($result['id']);

        // Verificar inserción
        $inserted = self::$orm->table('users')->where('email', '=', 'save@example.com')->firstArray();
        $this->assertNotNull($inserted);
        $this->assertEquals('Usuario Save', $inserted['name']);
    }

    public function testSaveExistingRecord(): void
    {
        // Test: save() debe detectar registro existente y actualizar
        // Primero obtener un ID existente
        $existingUser = self::$orm->table('users')->where('email', '=', 'alice@example.com')->firstArray();

        $existingUserUpdate = [
            'id' => $existingUser['id'], // Con ID = actualización
            'name' => 'Alice Actualizada',
            'email' => 'alice@example.com',
            'status' => 'super_active'
        ];

        $result = self::$orm->table('users')->save($existingUserUpdate);

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('updated', $result['operation']);

        // Verificar actualización
        $updated = self::$orm->table('users')->where('email', '=', 'alice@example.com')->firstArray();
        $this->assertEquals('Alice Actualizada', $updated['name']);
        $this->assertEquals('super_active', $updated['status']);
    }

    public function testSaveWithoutRequiredData(): void
    {
        // Test: save() debe fallar con datos vacíos
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('save requires data');

        self::$orm->table('users')->save([]); // Sin datos
    }

    //======================================================================
    // TESTS PARA MÉTODO createOrUpdate()
    //======================================================================

    public function testCreateOrUpdateNew(): void
    {
        // Test: createOrUpdate debe crear un nuevo registro (usar tabla users que tiene ID)
        $userData = [
            'name' => 'Usuario CreateOrUpdate',
            'email' => 'createorupdate@example.com',
            'status' => 'active'
        ];

        $result = self::$orm->table('users')->createOrUpdate(
            $userData,
            ['email' => 'createorupdate@example.com'], // Condiciones como clave => valor
            ['name', 'status']
        );

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('created', $result['operation']); // createOrUpdate devuelve 'created' no 'inserted'

        // Verificar creación
        $created = self::$orm->table('users')->where('email', '=', 'createorupdate@example.com')->firstArray();
        $this->assertNotNull($created);
        $this->assertEquals('Usuario CreateOrUpdate', $created['name']);
    }

    public function testCreateOrUpdateExisting(): void
    {
        // Test: createOrUpdate debe actualizar registro existente
        $updateData = [
            'sku' => 'P002', // Ya existe en datos de prueba
            'name' => 'Smartphone Actualizado',
            'price' => 899.99,
            'stock' => 30
        ];

        $result = self::$orm->table('products')->createOrUpdate(
            $updateData,
            ['sku' => 'P002'], // Condiciones como clave => valor
            ['name', 'price', 'stock']
        );

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('updated', $result['operation']);

        // Verificar actualización
        $updated = self::$orm->table('products')->where('sku', '=', 'P002')->firstArray();
        $this->assertEquals('Smartphone Actualizado', $updated['name']);
        $this->assertEquals(899.99, $updated['price']);
    }

    //======================================================================
    // TESTS DE INTEGRACIÓN Y CASOS EDGE
    //======================================================================

    public function testUpsertWithNullValues(): void
    {
        // Test: Manejo de valores NULL en upsert
        $dataWithNulls = [
            'sku' => 'NULL-TEST-001',
            'name' => 'Producto con Nulls',
            'price' => 100.00,
            'description' => null, // Valor NULL
            'stock' => 5
        ];

        $result = self::$orm->table('products')->upsert(
            $dataWithNulls,
            ['sku'],
            ['name', 'price', 'description', 'stock']
        );

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('inserted', $result['operation']);

        // Verificar que se manejó correctamente el NULL
        $inserted = self::$orm->table('products')->where('sku', '=', 'NULL-TEST-001')->firstArray();
        $this->assertNull($inserted['description']);
    }

    public function testUpsertWithSpecialCharacters(): void
    {
        // Test: Manejo de caracteres especiales en upsert
        $dataWithSpecialChars = [
            'sku' => 'SPECIAL-001',
            'name' => "Producto con 'comillas' y \"dobles\"",
            'price' => 150.00,
            'description' => 'Descripción con acentos: ñáéíóú',
            'stock' => 8
        ];

        $result = self::$orm->table('products')->upsert(
            $dataWithSpecialChars,
            ['sku'],
            ['name', 'price', 'description', 'stock']
        );

        $this->assertEquals('success', $result['status']);

        // Verificar que los caracteres especiales se guardaron correctamente
        $inserted = self::$orm->table('products')->where('sku', '=', 'SPECIAL-001')->firstArray();
        $this->assertStringContainsString("'comillas'", $inserted['name']);
        $this->assertStringContainsString('ñáéíóú', $inserted['description']);
    }

    public function testSaveWithAutoDetection(): void
    {
        // Test: save() debe detectar automáticamente si insertar o actualizar

        // Primero, insertar con save() (sin ID) - usar tabla users que tiene ID autoincremental
        $newRecord = [
            'name' => 'Auto Detection Test',
            'email' => 'autodetect@example.com',
            'status' => 'active'
        ];

        $result1 = self::$orm->table('users')->save($newRecord);
        $this->assertEquals('inserted', $result1['operation']);
        $insertedId = $result1['id'];

        // Luego, actualizar el mismo registro con save() (con ID)
        $updateRecord = [
            'id' => $insertedId, // Con ID para actualización
            'name' => 'Auto Detection Updated',
            'email' => 'autodetect@example.com',
            'status' => 'updated'
        ];

        $result2 = self::$orm->table('users')->save($updateRecord);
        $this->assertEquals('updated', $result2['operation']);

        // Verificar que se actualizó correctamente
        $final = self::$orm->table('users')->where('email', '=', 'autodetect@example.com')->firstArray();
        $this->assertEquals('Auto Detection Updated', $final['name']);
        $this->assertEquals('updated', $final['status']);
    }

    public function testPerformanceWithMultipleUpserts(): void
    {
        // Test: Rendimiento con múltiples operaciones upsert consecutivas
        $startTime = microtime(true);

        for ($i = 1; $i <= 10; $i++) {
            $data = [
                'sku' => 'PERF-TEST-' . str_pad((string)$i, 3, '0', STR_PAD_LEFT),
                'name' => "Producto Performance $i",
                'price' => 100.00 + $i,
                'stock' => $i * 5
            ];

            $result = self::$orm->table('products')->upsert(
                $data,
                ['sku'],
                ['name', 'price', 'stock']
            );

            $this->assertEquals('success', $result['status']);
        }

        $endTime = microtime(true);
        $executionTime = $endTime - $startTime;

        // Verificar que todas las operaciones fueron exitosas
        $count = self::$orm->table('products')
            ->where('sku', 'LIKE', 'PERF-TEST-%')
            ->count();

        $this->assertEquals(10, $count);

        // El tiempo debe ser razonable (menos de 2 segundos para 10 operaciones)
        $this->assertLessThan(
            2.0,
            $executionTime,
            "10 operaciones upsert tomaron demasiado tiempo: {$executionTime}s"
        );
    }
}
