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
    // ======================================================================
    // TESTS PARA MÉTODO upsert()
    // ======================================================================

    public function test_upsert_new_record(): void
    {
        // Test: Insertar un nuevo producto usando upsert
        $productData = [
            'sku' => 'UPSERT-NEW-001',
            'name' => 'Nuevo Producto Upsert',
            'price' => 299.99,
            'stock' => 15,
        ];

        $result = self::$orm->table('products')->upsert($productData, ['sku'], ['name', 'price', 'stock']); // Clave única // Campos a actualizar si existe

        static::assertIsArray($result);
        static::assertSame('success', $result['status']);
        static::assertSame('inserted', $result['operation']);
        static::assertSame(1, $result['rows_affected']);

        // Verificar que se insertó correctamente
        $inserted = self::$orm->table('products')->where('sku', '=', 'UPSERT-NEW-001')->firstArray();
        static::assertNotNull($inserted);
        static::assertSame('Nuevo Producto Upsert', $inserted['name']);
        static::assertSame(299.99, (float) $inserted['price']);
    }

    public function test_upsert_existing_record(): void
    {
        // Test: Actualizar un producto existente usando upsert
        $existingProduct = [
            'sku' => 'P001', // Ya existe en los datos de prueba
            'name' => 'Laptop Actualizada',
            'price' => 1299.99,
            'stock' => 25,
        ];

        $result = self::$orm->table('products')->upsert($existingProduct, ['sku'], ['name', 'price', 'stock']); // Clave única // Solo actualizar estos campos

        static::assertIsArray($result);
        static::assertSame('success', $result['status']);
        static::assertSame('updated', $result['operation']);
        static::assertSame(1, $result['rows_affected']);

        // Verificar que se actualizó correctamente
        $updated = self::$orm->table('products')->where('sku', '=', 'P001')->firstArray();
        static::assertNotNull($updated);
        static::assertSame('Laptop Actualizada', $updated['name']);
        static::assertSame(1299.99, (float) $updated['price']);
        static::assertSame(25, $updated['stock']);
    }

    public function test_upsert_with_multiple_unique_keys(): void
    {
        // Test: Upsert con múltiples claves únicas
        $userData = [
            'name' => 'Test Usuario',
            'email' => 'alice@example.com', // Ya existe
            'status' => 'super_active',
        ];

        $result = self::$orm->table('users')->upsert($userData, ['email'], ['name', 'status']); // Clave única // Campos a actualizar

        static::assertSame('success', $result['status']);
        static::assertSame('updated', $result['operation']);

        // Verificar actualización
        $updated = self::$orm->table('users')->where('email', '=', 'alice@example.com')->firstArray();
        static::assertSame('Test Usuario', $updated['name']);
        static::assertSame('super_active', $updated['status']);
    }

    public function test_upsert_with_empty_unique_keys(): void
    {
        // Test: Upsert debe fallar sin claves únicas
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsert requires unique keys');

        self::$orm->table('products')->upsert(['sku' => 'TEST', 'name' => 'Test'], [], ['name']); // Sin claves únicas - debe fallar
    }

    public function test_upsert_with_invalid_column_names(): void
    {
        // Test: Upsert debe validar nombres de columnas
        $this->expectException(VersaORMException::class);

        self::$orm->table('products')->upsert(['sku' => 'TEST', 'name' => 'Test'], ['invalid--column'], ['name']); // Nombre de columna inválido
    }

    // ======================================================================
    // TESTS PARA MÉTODO insertOrUpdate()
    // ======================================================================

    public function test_insert_or_update_new_record(): void
    {
        // Test: insertOrUpdate debe insertar un nuevo registro
        $userData = [
            'name' => 'New InsertOrUpdate User',
            'email' => 'insertupdate@example.com',
            'status' => 'active',
        ];

        $result = self::$orm->table('users')->insertOrUpdate($userData, ['email']);

        static::assertSame('success', $result['status']);
        static::assertSame('inserted', $result['operation']);

        // Verificar inserción
        $inserted = self::$orm->table('users')->where('email', '=', 'insertupdate@example.com')->firstArray();
        static::assertNotNull($inserted);
        static::assertSame('New InsertOrUpdate User', $inserted['name']);
    }

    public function test_insert_or_update_existing_record(): void
    {
        // Test: insertOrUpdate debe actualizar registro existente
        $updatedData = [
            'name' => 'Alice Updated',
            'email' => 'alice@example.com', // Ya existe
            'status' => 'updated',
        ];

        $result = self::$orm->table('users')->insertOrUpdate($updatedData, ['email']);

        static::assertSame('success', $result['status']);
        static::assertSame('updated', $result['operation']);

        // Verificar actualización
        $updated = self::$orm->table('users')->where('email', '=', 'alice@example.com')->firstArray();
        static::assertSame('Alice Updated', $updated['name']);
        static::assertSame('updated', $updated['status']);
    }

    // ======================================================================
    // TESTS PARA MÉTODO save()
    // ======================================================================

    public function test_save_new_record(): void
    {
        // Test: save() debe detectar registro nuevo e insertar
        $newUser = [
            'name' => 'Usuario Save',
            'email' => 'save@example.com',
            'status' => 'active',
        ];

        $result = self::$orm->table('users')->save($newUser); // Sin ID = inserción

        static::assertSame('success', $result['status']);
        static::assertSame('inserted', $result['operation']);
        static::assertIsNumeric($result['id']);

        // Verificar inserción
        $inserted = self::$orm->table('users')->where('email', '=', 'save@example.com')->firstArray();
        static::assertNotNull($inserted);
        static::assertSame('Usuario Save', $inserted['name']);
    }

    public function test_save_existing_record(): void
    {
        // Test: save() debe detectar registro existente y actualizar
        // Primero obtener un ID existente
        $existingUser = self::$orm->table('users')->where('email', '=', 'alice@example.com')->firstArray();

        $existingUserUpdate = [
            'id' => $existingUser['id'], // Con ID = actualización
            'name' => 'Alice Actualizada',
            'email' => 'alice@example.com',
            'status' => 'super_active',
        ];

        $result = self::$orm->table('users')->save($existingUserUpdate);

        static::assertSame('success', $result['status']);
        static::assertSame('updated', $result['operation']);

        // Verificar actualización
        $updated = self::$orm->table('users')->where('email', '=', 'alice@example.com')->firstArray();
        static::assertSame('Alice Actualizada', $updated['name']);
        static::assertSame('super_active', $updated['status']);
    }

    public function test_save_without_required_data(): void
    {
        // Test: save() debe fallar con datos vacíos
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('save requires data');

        self::$orm->table('users')->save([]); // Sin datos
    }

    // ======================================================================
    // TESTS PARA MÉTODO createOrUpdate()
    // ======================================================================

    public function test_create_or_update_new(): void
    {
        // Test: createOrUpdate debe crear un nuevo registro (usar tabla users que tiene ID)
        $userData = [
            'name' => 'Usuario CreateOrUpdate',
            'email' => 'createorupdate@example.com',
            'status' => 'active',
        ];

        $result = self::$orm
            ->table('users')
            ->createOrUpdate($userData, ['email' => 'createorupdate@example.com'], ['name', 'status']); // Condiciones como clave => valor

        static::assertSame('success', $result['status']);
        static::assertSame('created', $result['operation']); // createOrUpdate devuelve 'created' no 'inserted'

        // Verificar creación
        $created = self::$orm->table('users')->where('email', '=', 'createorupdate@example.com')->firstArray();
        static::assertNotNull($created);
        static::assertSame('Usuario CreateOrUpdate', $created['name']);
    }

    public function test_create_or_update_existing(): void
    {
        // Test: createOrUpdate debe actualizar registro existente
        $updateData = [
            'sku' => 'P002', // Ya existe en datos de prueba
            'name' => 'Smartphone Actualizado',
            'price' => 899.99,
            'stock' => 30,
        ];

        $result = self::$orm
            ->table('products')
            ->createOrUpdate($updateData, ['sku' => 'P002'], ['name', 'price', 'stock']); // Condiciones como clave => valor

        static::assertSame('success', $result['status']);
        static::assertSame('updated', $result['operation']);

        // Verificar actualización
        $updated = self::$orm->table('products')->where('sku', '=', 'P002')->firstArray();
        static::assertSame('Smartphone Actualizado', $updated['name']);
        static::assertSame(899.99, (float) $updated['price']);
    }

    // ======================================================================
    // TESTS DE INTEGRACIÓN Y CASOS EDGE
    // ======================================================================

    public function test_upsert_with_null_values(): void
    {
        // Test: Manejo de valores NULL en upsert
        $dataWithNulls = [
            'sku' => 'NULL-TEST-001',
            'name' => 'Producto con Nulls',
            'price' => 100.00,
            'description' => null, // Valor NULL
            'stock' => 5,
        ];

        $result = self::$orm
            ->table('products')
            ->upsert($dataWithNulls, ['sku'], ['name', 'price', 'description', 'stock']);

        static::assertSame('success', $result['status']);
        static::assertSame('inserted', $result['operation']);

        // Verificar que se manejó correctamente el NULL
        $inserted = self::$orm->table('products')->where('sku', '=', 'NULL-TEST-001')->firstArray();
        static::assertNull($inserted['description']);
    }

    public function test_upsert_with_special_characters(): void
    {
        // Test: Manejo de caracteres especiales en upsert
        $dataWithSpecialChars = [
            'sku' => 'SPECIAL-001',
            'name' => "Producto con 'comillas' y \"dobles\"",
            'price' => 150.00,
            'description' => 'Descripción con acentos: ñáéíóú',
            'stock' => 8,
        ];

        $result = self::$orm
            ->table('products')
            ->upsert($dataWithSpecialChars, ['sku'], ['name', 'price', 'description', 'stock']);

        static::assertSame('success', $result['status']);

        // Verificar que los caracteres especiales se guardaron correctamente
        $inserted = self::$orm->table('products')->where('sku', '=', 'SPECIAL-001')->firstArray();
        static::assertStringContainsString("'comillas'", $inserted['name']);
        static::assertStringContainsString('ñáéíóú', $inserted['description']);
    }

    public function test_save_with_auto_detection(): void
    {
        // Test: save() debe detectar automáticamente si insertar o actualizar

        // Primero, insertar con save() (sin ID) - usar tabla users que tiene ID autoincremental
        $newRecord = [
            'name' => 'Auto Detection Test',
            'email' => 'autodetect@example.com',
            'status' => 'active',
        ];

        $result1 = self::$orm->table('users')->save($newRecord);
        static::assertSame('inserted', $result1['operation']);
        $insertedId = $result1['id'];

        // Luego, actualizar el mismo registro con save() (con ID)
        $updateRecord = [
            'id' => $insertedId, // Con ID para actualización
            'name' => 'Auto Detection Updated',
            'email' => 'autodetect@example.com',
            'status' => 'updated',
        ];

        $result2 = self::$orm->table('users')->save($updateRecord);
        static::assertSame('updated', $result2['operation']);

        // Verificar que se actualizó correctamente
        $final = self::$orm->table('users')->where('email', '=', 'autodetect@example.com')->firstArray();
        static::assertSame('Auto Detection Updated', $final['name']);
        static::assertSame('updated', $final['status']);
    }

    public function test_performance_with_multiple_upserts(): void
    {
        // Test: Rendimiento con múltiples operaciones upsert consecutivas
        $startTime = microtime(true);

        for ($i = 1; $i <= 10; $i++) {
            $data = [
                'sku' => 'PERF-TEST-' . str_pad((string) $i, 3, '0', STR_PAD_LEFT),
                'name' => "Producto Performance {$i}",
                'price' => 100.00 + $i,
                'stock' => $i * 5,
            ];

            $result = self::$orm->table('products')->upsert($data, ['sku'], ['name', 'price', 'stock']);

            static::assertSame('success', $result['status']);
        }

        $endTime = microtime(true);
        $executionTime = $endTime - $startTime;

        // Verificar que todas las operaciones fueron exitosas
        $count = self::$orm->table('products')->where('sku', 'LIKE', 'PERF-TEST-%')->count();

        static::assertSame(10, $count);

        // El tiempo debe ser razonable (menos de 2 segundos para 10 operaciones)
        static::assertLessThan(
            2.0,
            $executionTime,
            "10 operaciones upsert tomaron demasiado tiempo: {$executionTime}s",
        );
    }
}
