<?php

declare(strict_types=1);

namespace VersaORM\Tests;

use VersaORM\VersaORMException;

/**
 * Tests exhaustivos para las operaciones de lote (Batch Operations) - Tarea 2.2.
 *
 * Este archivo contiene tests completos para:
 * - insertMany: Inserción masiva optimizada
 * - updateMany: Actualización masiva con condiciones
 * - deleteMany: Eliminación masiva con condiciones
 * - upsertMany: Inserción/actualización condicional masiva
 */
class QueryBuilderBatchTest extends TestCase
{
    //======================================================================
    // INSERT MANY TESTS
    //======================================================================

    public function testInsertManyBasic(): void
    {
        $records = [
            ['name' => 'Test User 1', 'email' => 'test1@example.com', 'status' => 'active'],
            ['name' => 'Test User 2', 'email' => 'test2@example.com', 'status' => 'active'],
            ['name' => 'Test User 3', 'email' => 'test3@example.com', 'status' => 'inactive'],
        ];

        $result = self::$orm->table('users')->insertMany($records);

        $this->assertIsArray($result);
        $this->assertEquals(3, $result['total_inserted']);
        $this->assertEquals(1, $result['batches_processed']);
        $this->assertEquals('success', $result['status']);

        // Verificar que los registros se insertaron
        $count = self::$orm->table('users')->where('name', 'LIKE', 'Test User%')->count();
        $this->assertEquals(3, $count);
    }

    public function testInsertManyWithBatchSize(): void
    {
        $records = [];
        for ($i = 1; $i <= 5; $i++) {
            $records[] = [
                'name' => "Batch User {$i}",
                'email' => "batch{$i}@example.com",
                'status' => 'active',
            ];
        }

        // Usar un batch size de 2 para probar el procesamiento en lotes
        $result = self::$orm->table('users')->insertMany($records, 2);

        $this->assertEquals(5, $result['total_inserted']);
        $this->assertEquals(3, $result['batches_processed']); // 5 registros en lotes de 2 = 3 lotes
        $this->assertEquals(2, $result['batch_size']);
        $this->assertEquals('success', $result['status']);
    }

    public function testInsertManyEmptyRecords(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('insertMany requires at least one record to insert');

        self::$orm->table('users')->insertMany([]);
    }

    public function testInsertManyInvalidRecord(): void
    {
        $records = [
            ['name' => 'Valid User', 'email' => 'valid@example.com'],
            'invalid_record', // String en lugar de array
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Record at index 1 is invalid or empty');

        self::$orm->table('users')->insertMany($records);
    }

    public function testInsertManyInconsistentStructure(): void
    {
        $records = [
            ['name' => 'User 1', 'email' => 'user1@example.com'],
            ['name' => 'User 2', 'email' => 'user2@example.com', 'extra_field' => 'extra'], // Campo adicional
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Record at index 1 has different columns');

        self::$orm->table('users')->insertMany($records);
    }

    public function testInsertManyInvalidBatchSize(): void
    {
        $records = [
            ['name' => 'Test User', 'email' => 'test@example.com'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Batch size must be between 1 and 10000');

        self::$orm->table('users')->insertMany($records, 0);
    }

    public function testInsertManyMaliciousColumnNames(): void
    {
        $records = [
            ['name; DROP TABLE users; --' => 'Malicious', 'email' => 'hack@example.com'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid or malicious column name detected');

        self::$orm->table('users')->insertMany($records);
    }

    //======================================================================
    // UPDATE MANY TESTS
    //======================================================================

    public function testUpdateManyBasic(): void
    {
        // Insertar datos de prueba con marcadores únicos
        $uniqueMarker = 'update_test_' . time() . '_' . mt_rand(1000, 9999);
        self::$orm->table('users')->insertMany([
            ['name' => 'Update Test 1', 'email' => 'update1@example.com', 'status' => $uniqueMarker . '_inactive'],
            ['name' => 'Update Test 2', 'email' => 'update2@example.com', 'status' => $uniqueMarker . '_inactive'],
            ['name' => 'Update Test 3', 'email' => 'update3@example.com', 'status' => $uniqueMarker . '_active'],
        ]);

        $result = self::$orm->table('users')
            ->where('status', '=', $uniqueMarker . '_inactive')
            ->updateMany(['status' => $uniqueMarker . '_updated'], 1000);

        $this->assertIsArray($result);
        $this->assertEquals(2, $result['rows_affected']);
        $this->assertEquals('success', $result['status']);

        // Verificar que se actualizaron los registros correctos
        $updatedCount = self::$orm->table('users')->where('status', '=', $uniqueMarker . '_updated')->count();
        $this->assertEquals(2, $updatedCount);
    }

    public function testUpdateManyWithMaxRecordsLimit(): void
    {
        // Insertar varios registros con marcador único
        $uniqueMarker = 'limit_test_' . time() . '_' . mt_rand(1000, 9999);
        $records = [];
        for ($i = 1; $i <= 5; $i++) {
            $records[] = [
                'name' => "Limit Test {$i}",
                'email' => "limit{$i}@example.com",
                'status' => $uniqueMarker . '_pending',
            ];
        }
        self::$orm->table('users')->insertMany($records);

        // Intentar actualizar con un límite menor
        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches('/exceeds the maximum limit/');

        self::$orm->table('users')
            ->where('status', '=', $uniqueMarker . '_pending')
            ->updateMany(['status' => 'active'], 2); // Límite de 2, pero hay 5 registros
    }

    public function testUpdateManyNoWhereCondition(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('updateMany requires WHERE conditions to prevent accidental mass updates');

        self::$orm->table('users')->updateMany(['status' => 'updated']);
    }

    public function testUpdateManyEmptyData(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('updateMany requires data to update');

        self::$orm->table('users')->where('id', '>', 0)->updateMany([]);
    }

    public function testUpdateManyMaliciousColumnNames(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid or malicious column name detected');

        self::$orm->table('users')
            ->where('id', '>', 0)
            ->updateMany(['name; DROP TABLE users; --' => 'malicious']);
    }

    public function testUpdateManyNoMatchingRecords(): void
    {
        $result = self::$orm->table('users')
            ->where('email', '=', 'nonexistent@example.com')
            ->updateMany(['status' => 'updated']);

        $this->assertEquals(0, $result['rows_affected']);
        $this->assertEquals('success', $result['status']);
        $this->assertEquals('No records matched the WHERE conditions', $result['message']);
    }

    //======================================================================
    // DELETE MANY TESTS
    //======================================================================

    public function testDeleteManyBasic(): void
    {
        // Insertar datos de prueba
        self::$orm->table('users')->insertMany([
            ['name' => 'Delete Test 1', 'email' => 'delete1@example.com', 'status' => 'to_delete'],
            ['name' => 'Delete Test 2', 'email' => 'delete2@example.com', 'status' => 'to_delete'],
            ['name' => 'Delete Test 3', 'email' => 'delete3@example.com', 'status' => 'keep'],
        ]);

        $result = self::$orm->table('users')
            ->where('status', '=', 'to_delete')
            ->deleteMany(1000);

        $this->assertIsArray($result);
        $this->assertEquals(2, $result['rows_affected']);
        $this->assertEquals('success', $result['status']);

        // Verificar que se eliminaron los registros correctos
        $deletedCount = self::$orm->table('users')->where('status', '=', 'to_delete')->count();
        $this->assertEquals(0, $deletedCount);

        $remainingCount = self::$orm->table('users')->where('status', '=', 'keep')->count();
        $this->assertEquals(1, $remainingCount);
    }

    public function testDeleteManyWithMaxRecordsLimit(): void
    {
        // Insertar varios registros
        $records = [];
        for ($i = 1; $i <= 5; $i++) {
            $records[] = [
                'name' => "Delete Limit Test {$i}",
                'email' => "delete_limit{$i}@example.com",
                'status' => 'bulk_delete',
            ];
        }
        self::$orm->table('users')->insertMany($records);

        // Intentar eliminar con un límite menor
        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches('/exceeds the maximum limit/');

        self::$orm->table('users')
            ->where('status', '=', 'bulk_delete')
            ->deleteMany(2); // Límite de 2, pero hay 5 registros
    }

    public function testDeleteManyNoWhereCondition(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('deleteMany requires WHERE conditions to prevent accidental mass deletions');

        self::$orm->table('users')->deleteMany();
    }

    public function testDeleteManyNoMatchingRecords(): void
    {
        $result = self::$orm->table('users')
            ->where('email', '=', 'nonexistent_delete@example.com')
            ->deleteMany();

        $this->assertEquals(0, $result['rows_affected']);
        $this->assertEquals('success', $result['status']);
        $this->assertEquals('No records matched the WHERE conditions', $result['message']);
    }

    //======================================================================
    // UPSERT MANY TESTS
    //======================================================================

    public function testUpsertManyBasic(): void
    {
        // Primero insertar algunos registros base
        $insertResult = self::$orm->table('products')->insertMany([
            ['sku' => 'UPSERT001', 'name' => 'Original Product 1', 'price' => 100.0],
            ['sku' => 'UPSERT002', 'name' => 'Original Product 2', 'price' => 200.0],
        ]);
        echo "\nDebug - Insert result: " . json_encode($insertResult) . "\n";

        // Verificar que se insertaron correctamente
        $originalProduct = self::$orm->table('products')->where('sku', '=', 'UPSERT001')->firstArray();
        echo "\nDebug - Original Product 1 after insert: " . json_encode($originalProduct) . "\n";

        // Ahora hacer upsert: actualizar existentes y crear nuevos
        $records = [
            ['sku' => 'UPSERT001', 'name' => 'Updated Product 1', 'price' => 150.0], // Actualizar
            ['sku' => 'UPSERT002', 'name' => 'Updated Product 2', 'price' => 250.0], // Actualizar
            ['sku' => 'UPSERT003', 'name' => 'New Product 3', 'price' => 300.0],      // Crear
        ];

        $result = self::$orm->table('products')
            ->upsertMany($records, ['sku'], ['name', 'price']);

        $this->assertIsArray($result);
        $this->assertEquals(3, $result['total_processed']);
        $this->assertEquals('success', $result['status']);
        $this->assertEquals(['sku'], $result['unique_keys']);
        $this->assertEquals(['name', 'price'], $result['update_columns']);

        // Verificar que los registros se actualizaron/crearon correctamente
        $updatedProduct1 = self::$orm->table('products')->where('sku', '=', 'UPSERT001')->firstArray();

        // Debug: Imprimir el producto completo
        echo "\nDebug - Updated Product 1: " . json_encode($updatedProduct1) . "\n";
        echo 'Price value: ' . var_export($updatedProduct1['price'], true) . "\n";
        echo 'Price type: ' . gettype($updatedProduct1['price']) . "\n";

        $this->assertEquals('Updated Product 1', $updatedProduct1['name']);
        $this->assertEquals(150.0, (float) $updatedProduct1['price'], 'Updated price should be 150.0', 0.01);

        $newProduct = self::$orm->table('products')->where('sku', '=', 'UPSERT003')->firstArray();
        $this->assertEquals('New Product 3', $newProduct['name']);
    }

    public function testUpsertManyEmptyRecords(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsertMany requires at least one record');

        self::$orm->table('products')->upsertMany([], ['sku']);
    }

    public function testUpsertManyEmptyUniqueKeys(): void
    {
        $records = [
            ['sku' => 'TEST001', 'name' => 'Test Product'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsertMany requires unique keys to detect duplicates');

        self::$orm->table('products')->upsertMany($records, []);
    }

    public function testUpsertManyMissingUniqueKey(): void
    {
        $records = [
            ['name' => 'Product without SKU', 'price' => 100.0], // Falta 'sku'
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Record at index 0 is missing unique key: sku');

        self::$orm->table('products')->upsertMany($records, ['sku']);
    }

    public function testUpsertManyInvalidUniqueKeyName(): void
    {
        $records = [
            ['sku' => 'TEST001', 'name' => 'Test Product'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid unique key name detected');

        self::$orm->table('products')->upsertMany($records, ['sku; DROP TABLE products; --']);
    }

    public function testUpsertManyInvalidUpdateColumnName(): void
    {
        $records = [
            ['sku' => 'TEST001', 'name' => 'Test Product'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid update column name detected');

        self::$orm->table('products')->upsertMany(
            $records,
            ['sku'],
            ['name; DROP TABLE products; --']
        );
    }

    //======================================================================
    // UPSERT INDIVIDUAL TESTS
    //======================================================================

    public function testUpsertIndividualBasic(): void
    {
        // Test básico de upsert para un registro individual
        $data = [
            'sku' => 'INDIVIDUAL_UPSERT001',
            'name' => 'Individual Upsert Product',
            'price' => 199.99
        ];

        $result = self::$orm->table('products')->upsert($data, ['sku']);

        $this->assertIsArray($result);
        $this->assertEquals('success', $result['status']);
        $this->assertEquals(1, $result['rows_affected']);
        $this->assertEquals(['sku'], $result['unique_keys']);
        $this->assertEquals('products', $result['table']);

        // Verificar que el registro se creó
        $created = self::$orm->table('products')->where('sku', '=', 'INDIVIDUAL_UPSERT001')->firstArray();
        $this->assertEquals('Individual Upsert Product', $created['name']);
        $this->assertEquals(199.99, (float) $created['price']);
    }

    public function testUpsertIndividualUpdate(): void
    {
        // Insertar registro inicial
        self::$orm->table('products')->insert([
            'sku' => 'INDIVIDUAL_UPDATE001',
            'name' => 'Original Individual Product',
            'price' => 100.0
        ]);

        // Hacer upsert para actualizar
        $updateData = [
            'sku' => 'INDIVIDUAL_UPDATE001',
            'name' => 'Updated Individual Product',
            'price' => 150.0
        ];

        $result = self::$orm->table('products')->upsert($updateData, ['sku'], ['name', 'price']);

        $this->assertEquals('success', $result['status']);
        $this->assertEquals(1, $result['rows_affected']);
        $this->assertEquals(['name', 'price'], $result['update_columns']);

        // Verificar que se actualizó
        $updated = self::$orm->table('products')->where('sku', '=', 'INDIVIDUAL_UPDATE001')->firstArray();
        $this->assertEquals('Updated Individual Product', $updated['name']);
        $this->assertEquals(150.0, (float) $updated['price']);
    }

    public function testUpsertIndividualWithoutUpdateColumns(): void
    {
        // Test upsert sin especificar columnas de actualización (debería actualizar todas)
        self::$orm->table('products')->insert([
            'sku' => 'NO_UPDATE_COLS001',
            'name' => 'Original Product',
            'price' => 100.0
        ]);

        $updateData = [
            'sku' => 'NO_UPDATE_COLS001',
            'name' => 'Updated Product',
            'price' => 200.0
        ];

        $result = self::$orm->table('products')->upsert($updateData, ['sku']);

        $this->assertEquals('success', $result['status']);
        $this->assertEquals([], $result['update_columns']); // Sin columnas específicas

        // Verificar que se actualizó
        $updated = self::$orm->table('products')->where('sku', '=', 'NO_UPDATE_COLS001')->firstArray();
        $this->assertEquals('Updated Product', $updated['name']);
        $this->assertEquals(200.0, (float) $updated['price']);
    }

    //======================================================================
    // EDGE CASES AND SECURITY TESTS
    //======================================================================

    public function testBatchOperationsWithLargeDatasets(): void
    {
        // Test con un dataset más grande para verificar el rendimiento
        $records = [];
        for ($i = 1; $i <= 100; $i++) {
            $records[] = [
                'name' => "Performance Test User {$i}",
                'email' => "perf{$i}@example.com",
                'status' => 'performance_test',
            ];
        }

        $startTime = microtime(true);
        $result = self::$orm->table('users')->insertMany($records, 25); // Lotes de 25
        $endTime = microtime(true);

        $this->assertEquals(100, $result['total_inserted']);
        $this->assertEquals(4, $result['batches_processed']); // 100/25 = 4 lotes
        $this->assertEquals('success', $result['status']);

        // Verificar que la operación fue razonablemente rápida (menos de 5 segundos)
        $executionTime = $endTime - $startTime;
        $this->assertLessThan(5.0, $executionTime, 'Batch operation should complete in reasonable time');

        // Limpiar después del test
        self::$orm->table('users')->where('status', '=', 'performance_test')->deleteMany(200);
    }

    public function testBatchOperationsTransactionIntegrity(): void
    {
        // Insertar registros válidos seguidos de uno inválido
        // Esto debería fallar y no insertar ningún registro del lote fallido
        $records = [
            ['name' => 'Valid 1', 'email' => 'valid1@integrity.com', 'status' => 'test'],
            ['name' => 'Valid 2', 'email' => 'valid2@integrity.com', 'status' => 'test'],
            // El siguiente registro podría causar un error si hay una restricción
            ['name' => str_repeat('x', 1000), 'email' => 'toolong@integrity.com', 'status' => 'test'], // Nombre muy largo
        ];

        try {
            self::$orm->table('users')->insertMany($records, 3); // Un solo lote
            // Si no falla, verificar que todos se insertaron
            $count = self::$orm->table('users')->where('status', '=', 'test')->count();
            $this->assertEquals(3, $count);
        } catch (\Exception $e) {
            // Si falla, verificar que ninguno se insertó
            $count = self::$orm->table('users')->where('status', '=', 'test')->count();
            $this->assertEquals(0, $count, 'No records should be inserted if batch fails');
        }
    }

    public function testBatchOperationsWithSpecialCharacters(): void
    {
        $records = [
            ['name' => "Test with 'quotes'", 'email' => 'quotes@example.com', 'status' => 'special'],
            ['name' => 'Test with "double quotes"', 'email' => 'dquotes@example.com', 'status' => 'special'],
            ['name' => 'Test with unicode: áéíóú ñ 测试', 'email' => 'unicode@example.com', 'status' => 'special'],
            ['name' => 'Test with emojis: 🚀💻🔥', 'email' => 'emoji@example.com', 'status' => 'special'],
        ];

        $result = self::$orm->table('users')->insertMany($records);

        $this->assertEquals(4, $result['total_inserted']);
        $this->assertEquals('success', $result['status']);

        // Verificar que los caracteres especiales se guardaron correctamente
        $unicodeUser = self::$orm->table('users')->where('email', '=', 'unicode@example.com')->firstArray();
        $this->assertStringContainsString('áéíóú', $unicodeUser['name']);
        $this->assertStringContainsString('测试', $unicodeUser['name']);

        $emojiUser = self::$orm->table('users')->where('email', '=', 'emoji@example.com')->firstArray();
        $this->assertStringContainsString('🚀', $emojiUser['name']);

        // Limpiar
        self::$orm->table('users')->where('status', '=', 'special')->deleteMany(10);
    }

    public function testBatchOperationsErrorRecovery(): void
    {
        // Test que verifica el manejo de errores y recuperación
        $validRecords = [
            ['name' => 'Recovery Test 1', 'email' => 'recovery1@example.com', 'status' => 'recovery'],
            ['name' => 'Recovery Test 2', 'email' => 'recovery2@example.com', 'status' => 'recovery'],
        ];

        // Insertar registros válidos primero
        $result = self::$orm->table('users')->insertMany($validRecords);
        $this->assertEquals(2, $result['total_inserted']);

        // Ahora intentar actualización con condiciones que no matchean
        $updateResult = self::$orm->table('users')
            ->where('status', '=', 'nonexistent_status')
            ->updateMany(['name' => 'Updated']);

        $this->assertEquals(0, $updateResult['rows_affected']);
        $this->assertEquals('No records matched the WHERE conditions', $updateResult['message']);

        // Verificar que los registros originales siguen intactos
        $count = self::$orm->table('users')->where('status', '=', 'recovery')->count();
        $this->assertEquals(2, $count);

        // Limpiar
        self::$orm->table('users')->where('status', '=', 'recovery')->deleteMany(5);
    }
}
