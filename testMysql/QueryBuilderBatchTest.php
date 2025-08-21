<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use Exception;
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
/**
 * @group mysql
 */
class QueryBuilderBatchTest extends TestCase
{
    // ======================================================================
    // INSERT MANY TESTS
    // ======================================================================

    public function test_insert_many_basic(): void
    {
        $records = [
            ['name' => 'Test User 1', 'email' => 'test1@example.com', 'status' => 'active'],
            ['name' => 'Test User 2', 'email' => 'test2@example.com', 'status' => 'active'],
            ['name' => 'Test User 3', 'email' => 'test3@example.com', 'status' => 'inactive'],
        ];

        $result = self::$orm->table('users')->insertMany($records);

        self::assertIsArray($result);
        self::assertSame(3, $result['total_inserted']);
        self::assertSame(1, $result['batches_processed']);
        self::assertSame('success', $result['status']);

        // Verificar que los registros se insertaron
        $count = self::$orm->table('users')->where('name', 'LIKE', 'Test User%')->count();
        self::assertSame(3, $count);
    }

    public function test_insert_many_with_batch_size(): void
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

        self::assertSame(5, $result['total_inserted']);
        self::assertSame(3, $result['batches_processed']); // 5 registros en lotes de 2 = 3 lotes
        self::assertSame(2, $result['batch_size']);
        self::assertSame('success', $result['status']);
    }

    public function test_insert_many_empty_records(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('insertMany requires at least one record to insert');

        self::$orm->table('users')->insertMany([]);
    }

    public function test_insert_many_invalid_record(): void
    {
        $records = [
            ['name' => 'Valid User', 'email' => 'valid@example.com'],
            'invalid_record', // String en lugar de array
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Record at index 1 is invalid or empty');

        self::$orm->table('users')->insertMany($records);
    }

    public function test_insert_many_inconsistent_structure(): void
    {
        $records = [
            ['name' => 'User 1', 'email' => 'user1@example.com'],
            ['name' => 'User 2', 'email' => 'user2@example.com', 'extra_field' => 'extra'], // Campo adicional
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Record at index 1 has different columns');

        self::$orm->table('users')->insertMany($records);
    }

    public function test_insert_many_invalid_batch_size(): void
    {
        $records = [
            ['name' => 'Test User', 'email' => 'test@example.com'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Batch size must be between 1 and 10000');

        self::$orm->table('users')->insertMany($records, 0);
    }

    public function test_insert_many_malicious_column_names(): void
    {
        $records = [
            ['name; DROP TABLE users; --' => 'Malicious', 'email' => 'hack@example.com'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid or malicious column name detected');

        self::$orm->table('users')->insertMany($records);
    }

    // ======================================================================
    // UPDATE MANY TESTS
    // ======================================================================

    public function test_update_many_basic(): void
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

        self::assertIsArray($result);
        self::assertSame(2, $result['rows_affected']);
        self::assertSame('success', $result['status']);

        // Verificar que se actualizaron los registros correctos
        $updatedCount = self::$orm->table('users')->where('status', '=', $uniqueMarker . '_updated')->count();
        self::assertSame(2, $updatedCount);
    }

    public function test_update_many_with_max_records_limit(): void
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
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/exceeds the maximum limit/');

        self::$orm->table('users')
            ->where('status', '=', $uniqueMarker . '_pending')
            ->updateMany(['status' => 'active'], 2); // Límite de 2, pero hay 5 registros
    }

    public function test_update_many_no_where_condition(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('updateMany requires WHERE conditions to prevent accidental mass updates');

        self::$orm->table('users')->updateMany(['status' => 'updated']);
    }

    public function test_update_many_empty_data(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('updateMany requires data to update');

        self::$orm->table('users')->where('id', '>', 0)->updateMany([]);
    }

    public function test_update_many_malicious_column_names(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid or malicious column name detected');

        self::$orm->table('users')
            ->where('id', '>', 0)
            ->updateMany(['name; DROP TABLE users; --' => 'malicious']);
    }

    public function test_update_many_no_matching_records(): void
    {
        $result = self::$orm->table('users')
            ->where('email', '=', 'nonexistent@example.com')
            ->updateMany(['status' => 'updated']);

        self::assertSame(0, $result['rows_affected']);
        self::assertSame('success', $result['status']);
        self::assertSame('No records matched the WHERE conditions', $result['message']);
    }

    // ======================================================================
    // DELETE MANY TESTS
    // ======================================================================

    public function test_delete_many_basic(): void
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

        self::assertIsArray($result);
        self::assertSame(2, $result['rows_affected']);
        self::assertSame('success', $result['status']);

        // Verificar que se eliminaron los registros correctos
        $deletedCount = self::$orm->table('users')->where('status', '=', 'to_delete')->count();
        self::assertSame(0, $deletedCount);

        $remainingCount = self::$orm->table('users')->where('status', '=', 'keep')->count();
        self::assertSame(1, $remainingCount);
    }

    public function test_delete_many_with_max_records_limit(): void
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
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/exceeds the maximum limit/');

        self::$orm->table('users')
            ->where('status', '=', 'bulk_delete')
            ->deleteMany(2); // Límite de 2, pero hay 5 registros
    }

    public function test_delete_many_no_where_condition(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('deleteMany requires WHERE conditions to prevent accidental mass deletions');

        self::$orm->table('users')->deleteMany();
    }

    public function test_delete_many_no_matching_records(): void
    {
        $result = self::$orm->table('users')
            ->where('email', '=', 'nonexistent_delete@example.com')
            ->deleteMany();

        self::assertSame(0, $result['rows_affected']);
        self::assertSame('success', $result['status']);
        self::assertSame('No records matched the WHERE conditions', $result['message']);
    }

    // ======================================================================
    // UPSERT MANY TESTS
    // ======================================================================

    public function test_upsert_many_basic(): void
    {
        // Primero insertar algunos registros base
        $insertResult = self::$orm->table('products')->insertMany([
            ['sku' => 'UPSERT001', 'name' => 'Original Product 1', 'price' => 100.0],
            ['sku' => 'UPSERT002', 'name' => 'Original Product 2', 'price' => 200.0],
        ]);

        // Verificar que se insertaron correctamente
        $originalProduct = self::$orm->table('products')->where('sku', '=', 'UPSERT001')->firstArray();

        // Ahora hacer upsert: actualizar existentes y crear nuevos
        $records = [
            ['sku' => 'UPSERT001', 'name' => 'Updated Product 1', 'price' => 150.0], // Actualizar
            ['sku' => 'UPSERT002', 'name' => 'Updated Product 2', 'price' => 250.0], // Actualizar
            ['sku' => 'UPSERT003', 'name' => 'New Product 3', 'price' => 300.0],      // Crear
        ];

        $result = self::$orm->table('products')
            ->upsertMany($records, ['sku'], ['name', 'price']);

        self::assertIsArray($result);
        self::assertSame(3, $result['total_processed']);
        self::assertSame('success', $result['status']);
        self::assertSame(['sku'], $result['unique_keys']);
        self::assertSame(['name', 'price'], $result['update_columns']);

        // Verificar que los registros se actualizaron/crearon correctamente
        $updatedProduct1 = self::$orm->table('products')->where('sku', '=', 'UPSERT001')->firstArray();

        // Debug: Imprimir el producto completo

        self::assertSame('Updated Product 1', $updatedProduct1['name']);
        self::assertEquals(150.0, (float) $updatedProduct1['price'], 'Updated price should be 150.0', 0.01);

        $newProduct = self::$orm->table('products')->where('sku', '=', 'UPSERT003')->firstArray();
        self::assertSame('New Product 3', $newProduct['name']);
    }

    public function test_upsert_many_empty_records(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsertMany requires at least one record');

        self::$orm->table('products')->upsertMany([], ['sku']);
    }

    public function test_upsert_many_empty_unique_keys(): void
    {
        $records = [
            ['sku' => 'TEST001', 'name' => 'Test Product'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsertMany requires unique keys to detect duplicates');

        self::$orm->table('products')->upsertMany($records, []);
    }

    public function test_upsert_many_missing_unique_key(): void
    {
        $records = [
            ['name' => 'Product without SKU', 'price' => 100.0], // Falta 'sku'
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Record at index 0 is missing unique key: sku');

        self::$orm->table('products')->upsertMany($records, ['sku']);
    }

    public function test_upsert_many_invalid_unique_key_name(): void
    {
        $records = [
            ['sku' => 'TEST001', 'name' => 'Test Product'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid unique key name detected');

        self::$orm->table('products')->upsertMany($records, ['sku; DROP TABLE products; --']);
    }

    public function test_upsert_many_invalid_update_column_name(): void
    {
        $records = [
            ['sku' => 'TEST001', 'name' => 'Test Product'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid update column name detected');

        self::$orm->table('products')->upsertMany(
            $records,
            ['sku'],
            ['name; DROP TABLE products; --'],
        );
    }

    // ======================================================================
    // UPSERT INDIVIDUAL TESTS
    // ======================================================================

    public function test_upsert_individual_basic(): void
    {
        // Test básico de upsert para un registro individual
        $data = [
            'sku' => 'INDIVIDUAL_UPSERT001',
            'name' => 'Individual Upsert Product',
            'price' => 199.99,
        ];

        $result = self::$orm->table('products')->upsert($data, ['sku']);

        self::assertIsArray($result);
        self::assertSame('success', $result['status']);
        self::assertSame(1, $result['rows_affected']);
        self::assertSame(['sku'], $result['unique_keys']);
        self::assertSame('products', $result['table']);

        // Verificar que el registro se creó
        $created = self::$orm->table('products')->where('sku', '=', 'INDIVIDUAL_UPSERT001')->firstArray();
        self::assertSame('Individual Upsert Product', $created['name']);
        self::assertSame(199.99, (float) $created['price']);
    }

    public function test_upsert_individual_update(): void
    {
        // Insertar registro inicial
        self::$orm->table('products')->insert([
            'sku' => 'INDIVIDUAL_UPDATE001',
            'name' => 'Original Individual Product',
            'price' => 100.0,
        ]);

        // Hacer upsert para actualizar
        $updateData = [
            'sku' => 'INDIVIDUAL_UPDATE001',
            'name' => 'Updated Individual Product',
            'price' => 150.0,
        ];

        $result = self::$orm->table('products')->upsert($updateData, ['sku'], ['name', 'price']);

        self::assertSame('success', $result['status']);
        self::assertSame(1, $result['rows_affected']);
        self::assertSame(['name', 'price'], $result['update_columns']);

        // Verificar que se actualizó
        $updated = self::$orm->table('products')->where('sku', '=', 'INDIVIDUAL_UPDATE001')->firstArray();
        self::assertSame('Updated Individual Product', $updated['name']);
        self::assertSame(150.0, (float) $updated['price']);
    }

    public function test_upsert_individual_without_update_columns(): void
    {
        // Test upsert sin especificar columnas de actualización (debería actualizar todas)
        self::$orm->table('products')->insert([
            'sku' => 'NO_UPDATE_COLS001',
            'name' => 'Original Product',
            'price' => 100.0,
        ]);

        $updateData = [
            'sku' => 'NO_UPDATE_COLS001',
            'name' => 'Updated Product',
            'price' => 200.0,
        ];

        $result = self::$orm->table('products')->upsert($updateData, ['sku']);

        self::assertSame('success', $result['status']);
        self::assertSame([], $result['update_columns']); // Sin columnas específicas

        // Verificar que se actualizó
        $updated = self::$orm->table('products')->where('sku', '=', 'NO_UPDATE_COLS001')->firstArray();
        self::assertSame('Updated Product', $updated['name']);
        self::assertSame(200.0, (float) $updated['price']);
    }

    // ======================================================================
    // EDGE CASES AND SECURITY TESTS
    // ======================================================================

    public function test_batch_operations_with_large_datasets(): void
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

        self::assertSame(100, $result['total_inserted']);
        self::assertSame(4, $result['batches_processed']); // 100/25 = 4 lotes
        self::assertSame('success', $result['status']);

        // Verificar que la operación fue razonablemente rápida (menos de 5 segundos)
        $executionTime = $endTime - $startTime;
        self::assertLessThan(5.0, $executionTime, 'Batch operation should complete in reasonable time');

        // Limpiar después del test
        self::$orm->table('users')->where('status', '=', 'performance_test')->deleteMany(200);
    }

    public function test_batch_operations_transaction_integrity(): void
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
            self::assertSame(3, $count);
        } catch (Exception $e) {
            // Si falla, verificar que ninguno se insertó
            $count = self::$orm->table('users')->where('status', '=', 'test')->count();
            self::assertSame(0, $count, 'No records should be inserted if batch fails');
        }
    }

    public function test_batch_operations_with_special_characters(): void
    {
        $records = [
            ['name' => "Test with 'quotes'", 'email' => 'quotes@example.com', 'status' => 'special'],
            ['name' => 'Test with "double quotes"', 'email' => 'dquotes@example.com', 'status' => 'special'],
            ['name' => 'Test with unicode: áéíóú ñ 测试', 'email' => 'unicode@example.com', 'status' => 'special'],
            ['name' => 'Test with emojis: 🚀💻🔥', 'email' => 'emoji@example.com', 'status' => 'special'],
        ];

        $result = self::$orm->table('users')->insertMany($records);

        self::assertSame(4, $result['total_inserted']);
        self::assertSame('success', $result['status']);

        // Verificar que los caracteres especiales se guardaron correctamente
        $unicodeUser = self::$orm->table('users')->where('email', '=', 'unicode@example.com')->firstArray();
        self::assertStringContainsString('áéíóú', $unicodeUser['name']);
        self::assertStringContainsString('测试', $unicodeUser['name']);

        $emojiUser = self::$orm->table('users')->where('email', '=', 'emoji@example.com')->firstArray();
        self::assertStringContainsString('🚀', $emojiUser['name']);

        // Limpiar
        self::$orm->table('users')->where('status', '=', 'special')->deleteMany(10);
    }

    public function test_batch_operations_error_recovery(): void
    {
        // Test que verifica el manejo de errores y recuperación
        $validRecords = [
            ['name' => 'Recovery Test 1', 'email' => 'recovery1@example.com', 'status' => 'recovery'],
            ['name' => 'Recovery Test 2', 'email' => 'recovery2@example.com', 'status' => 'recovery'],
        ];

        // Insertar registros válidos primero
        $result = self::$orm->table('users')->insertMany($validRecords);
        self::assertSame(2, $result['total_inserted']);

        // Ahora intentar actualización con condiciones que no matchean
        $updateResult = self::$orm->table('users')
            ->where('status', '=', 'nonexistent_status')
            ->updateMany(['name' => 'Updated']);

        self::assertSame(0, $updateResult['rows_affected']);
        self::assertSame('No records matched the WHERE conditions', $updateResult['message']);

        // Verificar que los registros originales siguen intactos
        $count = self::$orm->table('users')->where('status', '=', 'recovery')->count();
        self::assertSame(2, $count);

        // Limpiar
        self::$orm->table('users')->where('status', '=', 'recovery')->deleteMany(5);
    }
}
