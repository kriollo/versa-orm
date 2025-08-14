<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaORMException;

/**
 * Tests exhaustivos para las operaciones REPLACE INTO y UPSERT individuales - Tarea 2.2.
 *
 * Este archivo contiene tests completos para:
 * - replaceInto: Sustitución completa de un registro
 * - replaceIntoMany: Sustitución masiva optimizada
 * - upsert: Inserción/actualización condicional para un registro
 */
class QueryBuilderReplaceAndUpsertTest extends TestCase
{
    /** @var array<string, mixed> */
    protected static array $config;
    // ======================================================================
    // REPLACE INTO TESTS
    // ======================================================================

    public function testReplaceIntoBasic(): void
    {
        // Insertar un registro inicial
        $initialData = [
            'sku' => 'REPLACE001',
            'name' => 'Original Product',
            'price' => 100.0,
        ];
        self::$orm->table('products')->insert($initialData);

        // Verificar que se insertó
        $original = self::$orm->table('products')->where('sku', '=', 'REPLACE001')->firstArray();
        self::assertSame('Original Product', $original['name']);
        self::assertSame(100.0, (float) $original['price']);

        // Ahora usar replaceInto para reemplazar completamente el registro
        $replaceData = [
            'sku' => 'REPLACE001',
            'name' => 'Replaced Product',
            'price' => 200.0,
            'description' => 'New description', // Campo adicional
        ];

        $result = self::$orm->table('products')->replaceInto($replaceData);

        self::assertIsArray($result);
        self::assertSame('success', $result['status']);
        self::assertSame('replaced', $result['operation']);
        self::assertSame(1, $result['rows_affected']);
        self::assertSame('products', $result['table']);

        // Verificar que el registro fue "reemplazado" (en PG emulación conserva no especificados)
        $replaced = self::$orm->table('products')->where('sku', '=', 'REPLACE001')->firstArray();
        self::assertSame('Replaced Product', $replaced['name']);
        self::assertSame(200.0, (float) $replaced['price']);
        self::assertSame('New description', $replaced['description']);
    }

    public function testReplaceIntoNewRecord(): void
    {
        // Usar replaceInto para insertar un registro completamente nuevo
        $newData = [
            'sku' => 'REPLACE_NEW001',
            'name' => 'New Product via Replace',
            'price' => 150.0,
        ];

        $result = self::$orm->table('products')->replaceInto($newData);

        self::assertSame('success', $result['status']);
        self::assertSame('replaced', $result['operation']);
        self::assertSame(1, $result['rows_affected']);

        // Verificar que se creó el nuevo registro
        $new = self::$orm->table('products')->where('sku', '=', 'REPLACE_NEW001')->firstArray();
        self::assertSame('New Product via Replace', $new['name']);
        self::assertSame(150.0, (float) $new['price']);
    }

    public function testReplaceIntoEmptyData(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('replaceInto requires data to replace/insert');

        self::$orm->table('products')->replaceInto([]);
    }

    public function testReplaceIntoMaliciousColumnNames(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid or malicious column name detected');

        self::$orm->table('products')->replaceInto([
            'sku; DROP TABLE products; --' => 'malicious',
            'name' => 'Test Product',
        ]);
    }

    public function testReplaceIntoNonMySQLDriver(): void
    {
        // En PostgreSQL ahora emulamos REPLACE como UPSERT, no debe lanzar excepción
        $result = self::$orm->table('products')->replaceInto(['sku' => 'TEST', 'name' => 'Test']);
        self::assertIsArray($result);
        self::assertSame('success', $result['status'] ?? 'success');
        self::assertSame('products', $result['table']);
    }

    // ======================================================================
    // REPLACE INTO MANY TESTS
    // ======================================================================

    public function testReplaceIntoManyBasic(): void
    {
        // Insertar algunos registros iniciales
        $initialRecords = [
            ['sku' => 'REPLACE_MANY001', 'name' => 'Original 1', 'price' => 100.0],
            ['sku' => 'REPLACE_MANY002', 'name' => 'Original 2', 'price' => 200.0],
        ];
        self::$orm->table('products')->insertMany($initialRecords);

        // Ahora usar replaceIntoMany para reemplazar y agregar nuevos
        $replaceRecords = [
            ['sku' => 'REPLACE_MANY001', 'name' => 'Replaced 1', 'price' => 150.0, 'description' => 'Updated 1'],
            ['sku' => 'REPLACE_MANY002', 'name' => 'Replaced 2', 'price' => 250.0, 'description' => 'Updated 2'],
            ['sku' => 'REPLACE_MANY003', 'name' => 'New Product 3', 'price' => 300.0, 'description' => 'New 3'],
        ];

        $result = self::$orm->table('products')->replaceIntoMany($replaceRecords);

        self::assertIsArray($result);
        self::assertSame(3, $result['total_replaced']);
        self::assertSame(1, $result['batches_processed']);
        self::assertSame('success', $result['status']);
        self::assertSame(3, $result['total_records']);

        // Verificar que los registros fueron reemplazados correctamente
        $replaced1 = self::$orm->table('products')->where('sku', '=', 'REPLACE_MANY001')->firstArray();
        self::assertSame('Replaced 1', $replaced1['name']);
        self::assertSame('Updated 1', $replaced1['description']);

        $newProduct = self::$orm->table('products')->where('sku', '=', 'REPLACE_MANY003')->firstArray();
        self::assertSame('New Product 3', $newProduct['name']);
        self::assertSame('New 3', $newProduct['description']);
    }

    public function testReplaceIntoManyWithBatchSize(): void
    {
        $records = [];

        for ($i = 1; $i <= 5; ++$i) {
            $records[] = [
                'sku' => "BATCH_REPLACE{$i}",
                'name' => "Batch Replace Product {$i}",
                'price' => $i * 100.0,
            ];
        }

        // Usar un batch size de 2
        $result = self::$orm->table('products')->replaceIntoMany($records, 2);

        self::assertSame(5, $result['total_replaced']);
        self::assertSame(3, $result['batches_processed']); // 5 registros en lotes de 2 = 3 lotes
        self::assertSame(2, $result['batch_size']);
        self::assertSame('success', $result['status']);

        // Verificar que todos los registros se crearon
        $count = self::$orm->table('products')->where('sku', 'LIKE', 'BATCH_REPLACE%')->count();
        self::assertSame(5, $count);
    }

    public function testReplaceIntoManyEmptyRecords(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('replaceIntoMany requires at least one record');

        self::$orm->table('products')->replaceIntoMany([]);
    }

    public function testReplaceIntoManyInconsistentStructure(): void
    {
        $records = [
            ['sku' => 'CONSIST001', 'name' => 'Product 1'],
            ['sku' => 'CONSIST002', 'name' => 'Product 2', 'extra_field' => 'extra'], // Campo adicional
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Record at index 1 has different columns');

        self::$orm->table('products')->replaceIntoMany($records);
    }

    public function testReplaceIntoManyInvalidBatchSize(): void
    {
        $records = [
            ['sku' => 'TEST001', 'name' => 'Test Product'],
        ];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Batch size must be between 1 and 10000');

        self::$orm->table('products')->replaceIntoMany($records, 0);
    }

    // ======================================================================
    // UPSERT INDIVIDUAL TESTS
    // ======================================================================

    public function testUpsertInsertNewRecord(): void
    {
        // Test upsert que debería insertar un nuevo registro
        $data = [
            'sku' => 'UPSERT_NEW001',
            'name' => 'New Upsert Product',
            'price' => 199.99,
        ];

        $result = self::$orm->table('products')->upsert($data, ['sku']);

        self::assertIsArray($result);
        self::assertSame('success', $result['status']);
        self::assertContains($result['operation'], ['inserted', 'updated']);
        self::assertSame(1, $result['rows_affected']);
        self::assertSame(['sku'], $result['unique_keys']);
        self::assertSame('products', $result['table']);

        // Verificar que el registro se creó
        $created = self::$orm->table('products')->where('sku', '=', 'UPSERT_NEW001')->firstArray();
        self::assertSame('New Upsert Product', $created['name']);
        self::assertSame(199.99, (float) $created['price']);
    }

    public function testUpsertUpdateExistingRecord(): void
    {
        // Primero insertar un registro
        $initialData = [
            'sku' => 'UPSERT_UPDATE001',
            'name' => 'Original Upsert Product',
            'price' => 100.0,
        ];
        self::$orm->table('products')->insert($initialData);

        // Ahora hacer upsert para actualizar
        $updateData = [
            'sku' => 'UPSERT_UPDATE001',
            'name' => 'Updated Upsert Product',
            'price' => 150.0,
        ];

        $result = self::$orm->table('products')->upsert($updateData, ['sku'], ['name', 'price']);

        self::assertSame('success', $result['status']);
        self::assertSame(1, $result['rows_affected']);
        self::assertSame(['sku'], $result['unique_keys']);
        self::assertSame(['name', 'price'], $result['update_columns']);

        // Verificar que el registro se actualizó
        $updated = self::$orm->table('products')->where('sku', '=', 'UPSERT_UPDATE001')->firstArray();
        self::assertSame('Updated Upsert Product', $updated['name']);
        self::assertSame(150.0, (float) $updated['price']);
    }

    public function testUpsertWithMultipleUniqueKeys(): void
    {
        // Test upsert con múltiples claves únicas
        $data = [
            'sku' => 'MULTI_KEY001',
            'category' => 'electronics',
            'name' => 'Multi Key Product',
            'price' => 299.99,
        ];

        $result = self::$orm->table('products')->upsert($data, ['sku', 'category']);

        self::assertSame('success', $result['status']);
        self::assertSame(['sku', 'category'], $result['unique_keys']);

        // Verificar que el registro se creó
        $created = self::$orm->table('products')
            ->where('sku', '=', 'MULTI_KEY001')
            ->where('category', '=', 'electronics')
            ->firstArray()
        ;
        self::assertSame('Multi Key Product', $created['name']);
    }

    public function testUpsertEmptyData(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsert requires data to insert/update');

        self::$orm->table('products')->upsert([], ['sku']);
    }

    public function testUpsertEmptyUniqueKeys(): void
    {
        $data = ['sku' => 'TEST001', 'name' => 'Test Product'];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsert requires unique keys to detect duplicates');

        self::$orm->table('products')->upsert($data, []);
    }

    public function testUpsertMissingUniqueKey(): void
    {
        $data = ['name' => 'Product without SKU', 'price' => 100.0]; // Falta 'sku'

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Record is missing unique key: sku');

        self::$orm->table('products')->upsert($data, ['sku']);
    }

    public function testUpsertInvalidUniqueKeyName(): void
    {
        $data = ['sku' => 'TEST001', 'name' => 'Test Product'];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid unique key name detected');

        self::$orm->table('products')->upsert($data, ['sku; DROP TABLE products; --']);
    }

    public function testUpsertInvalidUpdateColumnName(): void
    {
        $data = ['sku' => 'TEST001', 'name' => 'Test Product'];

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid update column name detected');

        self::$orm->table('products')->upsert(
            $data,
            ['sku'],
            ['name; DROP TABLE products; --'],
        );
    }

    public function testUpsertWithSpecificUpdateColumns(): void
    {
        // Insertar registro inicial
        $initialData = [
            'sku' => 'SPECIFIC_UPDATE001',
            'name' => 'Original Name',
            'price' => 100.0,
            'description' => 'Original Description',
        ];
        self::$orm->table('products')->insert($initialData);

        // Hacer upsert especificando solo actualizar el precio
        $updateData = [
            'sku' => 'SPECIFIC_UPDATE001',
            'name' => 'New Name', // Este no debería actualizarse
            'price' => 200.0,     // Este sí debería actualizarse
            'description' => 'New Description', // Este no debería actualizarse
        ];

        $result = self::$orm->table('products')->upsert(
            $updateData,
            ['sku'],
            ['price'], // Solo actualizar el precio
        );

        self::assertSame('success', $result['status']);
        self::assertSame(['price'], $result['update_columns']);

        // Verificar que solo se actualizó el precio
        $updated = self::$orm->table('products')->where('sku', '=', 'SPECIFIC_UPDATE001')->firstArray();
        self::assertSame('Original Name', $updated['name']); // No debería cambiar
        self::assertSame(200.0, (float) $updated['price']); // Debería cambiar
        self::assertSame('Original Description', $updated['description']); // No debería cambiar
    }

    // ======================================================================
    // INTEGRATION AND EDGE CASES
    // ======================================================================

    public function testUpsertWithSpecialCharacters(): void
    {
        $data = [
            'sku' => 'SPECIAL_CHARS001',
            'name' => "Product with 'quotes' and \"double quotes\"",
            'price' => 99.99,
            'description' => 'Unicode: áéíóú ñ 测试 🚀💻',
        ];

        $result = self::$orm->table('products')->upsert($data, ['sku']);

        self::assertSame('success', $result['status']);

        // Verificar que los caracteres especiales se guardaron correctamente
        $saved = self::$orm->table('products')->where('sku', '=', 'SPECIAL_CHARS001')->firstArray();
        self::assertStringContainsString("'quotes'", $saved['name']);
        self::assertStringContainsString('"double quotes"', $saved['name']);
        self::assertStringContainsString('áéíóú', $saved['description']);
        self::assertStringContainsString('测试', $saved['description']);
        self::assertStringContainsString('🚀', $saved['description']);
    }

    public function testReplaceIntoVsUpsertBehaviorDifference(): void
    {
        // Insertar registro inicial con campo extra
        $initialData = [
            'sku' => 'BEHAVIOR_TEST001',
            'name' => 'Original Product',
            'price' => 100.0,
            'description' => 'Original Description',
            'category' => 'original_category',
        ];
        self::$orm->table('products')->insert($initialData);

        // Test 1: REPLACE INTO - debería reemplazar completamente el registro
        $replaceData = [
            'sku' => 'BEHAVIOR_TEST001',
            'name' => 'Replaced Product',
            'price' => 200.0,
            // Nota: no incluimos description ni category
        ];

        self::$orm->table('products')->replaceInto($replaceData);

        $afterReplace = self::$orm->table('products')->where('sku', '=', 'BEHAVIOR_TEST001')->firstArray();
        self::assertSame('Replaced Product', $afterReplace['name']);
        self::assertSame(200.0, (float) $afterReplace['price']);
        // En PostgreSQL (emulación) REPLACE preserva campos no especificados
        self::assertSame('Original Description', $afterReplace['description']);
        self::assertSame('original_category', $afterReplace['category']);

        // Reinsertar registro inicial para test de upsert
        self::$orm->table('products')->delete(['sku' => 'BEHAVIOR_TEST001']);
        self::$orm->table('products')->insert($initialData);

        // Test 2: UPSERT - debería actualizar solo los campos especificados
        $upsertData = [
            'sku' => 'BEHAVIOR_TEST001',
            'name' => 'Upserted Product',
            'price' => 300.0,
            // Nota: no incluimos description ni category
        ];

        self::$orm->table('products')->upsert($upsertData, ['sku'], ['name', 'price']);

        $afterUpsert = self::$orm->table('products')->where('sku', '=', 'BEHAVIOR_TEST001')->firstArray();
        self::assertSame('Upserted Product', $afterUpsert['name']);
        self::assertSame(300.0, (float) $afterUpsert['price']);
        // UPSERT debería haber preservado los campos no especificados
        self::assertSame('Original Description', $afterUpsert['description']);
        self::assertSame('original_category', $afterUpsert['category']);
    }

    public function testLargeDatasetPerformance(): void
    {
        // Test de rendimiento con dataset mediano
        $records = [];

        for ($i = 1; $i <= 50; ++$i) {
            $records[] = [
                'sku' => "PERF_REPLACE{$i}",
                'name' => "Performance Test Product {$i}",
                'price' => $i * 10.0,
                'description' => "Performance test description for product {$i}",
            ];
        }

        $startTime = microtime(true);
        $result = self::$orm->table('products')->replaceIntoMany($records, 10);
        $endTime = microtime(true);

        self::assertSame(50, $result['total_replaced']);
        self::assertSame(5, $result['batches_processed']); // 50/10 = 5 lotes
        self::assertSame('success', $result['status']);

        // Verificar que la operación fue razonablemente rápida (menos de 3 segundos)
        $executionTime = $endTime - $startTime;
        self::assertLessThan(3.0, $executionTime, 'ReplaceIntoMany should complete in reasonable time');

        // Verificar que todos los registros se crearon
        $count = self::$orm->table('products')->where('sku', 'LIKE', 'PERF_REPLACE%')->count();
        self::assertSame(50, $count);

        // Limpiar
        self::$orm->table('products')->where('sku', 'LIKE', 'PERF_REPLACE%')->deleteMany(100);
    }

    /**
     * @before
     */
    protected function setUpConfig(): void
    {
        if (!isset(self::$config)) {
            self::$config = self::$orm->getConfig();
        }
    }
}
