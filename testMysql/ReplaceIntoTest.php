<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;
use VersaORM\VersaORMException;

use function strlen;

/**
 * Test unitarios para operaciones REPLACE INTO.
 *
 * Cubre el método replaceInto() implementado en la Tarea 2.2.
 * Nota: REPLACE INTO es específico de MySQL - otros drivers usan fallback.
 */

/**
 * @group mysql
 */
class ReplaceIntoTest extends TestCase
{
    // ======================================================================
    // TESTS PARA MÉTODO replaceInto()
    // ======================================================================

    public function testReplaceIntoNewRecord(): void
    {
        // Test: REPLACE INTO debe insertar un nuevo registro
        $newProduct = [
            'sku' => 'REPLACE-NEW-001',
            'name' => 'Producto Replace Nuevo',
            'price' => 199.99,
            'stock' => 15,
            'description' => 'Producto creado con REPLACE INTO',
        ];

        $result = self::$orm->table('products')->replaceInto($newProduct);

        self::assertIsArray($result);
        self::assertSame('success', $result['status']);
        self::assertSame(1, $result['rows_affected']);

        // Verificar que se insertó correctamente
        $inserted = self::$orm->table('products')->where('sku', '=', 'REPLACE-NEW-001')->firstArray();
        self::assertNotNull($inserted);
        self::assertSame('Producto Replace Nuevo', $inserted['name']);
        self::assertEquals(199.99, (float) $inserted['price']);
        self::assertSame('Producto creado con REPLACE INTO', $inserted['description']);
    }

    public function testReplaceIntoExistingRecord(): void
    {
        // Test: REPLACE INTO debe reemplazar completamente un registro existente

        // Insertar un registro inicial
        $initialProduct = [
            'sku' => 'REPLACE-EXIST-001',
            'name' => 'Producto Original',
            'price' => 100.00,
            'stock' => 10,
            'description' => 'Descripción original',
        ];

        self::$orm->table('products')->insert($initialProduct);

        // Ahora usar REPLACE INTO para reemplazar completamente
        $replacementProduct = [
            'sku' => 'REPLACE-EXIST-001', // Misma clave única
            'name' => 'Producto Reemplazado',
            'price' => 250.00,
            'stock' => 25,
            // Nota: No incluimos 'description' para verificar que se pierde
        ];

        $result = self::$orm->table('products')->replaceInto($replacementProduct);

        self::assertSame('success', $result['status']);
        self::assertSame(1, $result['rows_affected']);

        // Verificar que se reemplazó completamente (description debe ser NULL)
        $replaced = self::$orm->table('products')->where('sku', '=', 'REPLACE-EXIST-001')->firstArray();
        self::assertNotNull($replaced);
        self::assertSame('Producto Reemplazado', $replaced['name']);
        self::assertEquals(250.00, (float) $replaced['price']);
        self::assertSame(25, $replaced['stock']);

        // La descripción debe ser NULL porque no se incluyó en el reemplazo
        self::assertNull($replaced['description']);
    }

    public function testReplaceIntoWithAllFields(): void
    {
        // Test: REPLACE INTO con todos los campos disponibles en el esquema
        $completeProduct = [
            'sku' => 'REPLACE-COMPLETE-001',
            'name' => 'Producto Completo',
            'price' => 399.99,
            'stock' => 50,
            'description' => 'Descripción completa del producto',
            'category' => 'Electronics',
        ];

        $result = self::$orm->table('products')->replaceInto($completeProduct);

        self::assertSame('success', $result['status']);
        self::assertSame(1, $result['rows_affected']);

        // Verificar que todos los campos se guardaron
        $inserted = self::$orm->table('products')->where('sku', '=', 'REPLACE-COMPLETE-001')->firstArray();
        self::assertSame('Producto Completo', $inserted['name']);
        self::assertEquals(399.99, (float) $inserted['price']);
        self::assertSame(50, $inserted['stock']);
        self::assertSame('Descripción completa del producto', $inserted['description']);
        self::assertSame('Electronics', $inserted['category']);
    }

    public function testReplaceIntoWithNullValues(): void
    {
        // Test: REPLACE INTO debe manejar valores NULL correctamente
        $productWithNulls = [
            'sku' => 'REPLACE-NULL-001',
            'name' => 'Producto con NULLs',
            'price' => 150.00,
            'stock' => 20,
            'description' => null, // Valor NULL explícito
            'category' => null,
        ];

        $result = self::$orm->table('products')->replaceInto($productWithNulls);

        self::assertSame('success', $result['status']);

        // Verificar que los NULLs se manejaron correctamente
        $inserted = self::$orm->table('products')->where('sku', '=', 'REPLACE-NULL-001')->firstArray();
        self::assertSame('Producto con NULLs', $inserted['name']);
        self::assertEquals(150.00, (float) $inserted['price']);
        self::assertNull($inserted['description']);
        self::assertNull($inserted['category']);
    }

    public function testReplaceIntoWithEmptyData(): void
    {
        // Test: REPLACE INTO debe fallar con datos vacíos
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('replaceInto requires data');

        self::$orm->table('products')->replaceInto([]);
    }

    public function testReplaceIntoWithSpecialCharacters(): void
    {
        // Test: REPLACE INTO debe manejar caracteres especiales correctamente
        $productWithSpecialChars = [
            'sku' => 'REPLACE-SPECIAL-001',
            'name' => "Producto 'con' \"comillas\" & símbolos",
            'price' => 75.50,
            'stock' => 12,
            'description' => 'Descripción con acentos: ñáéíóú y símbolos @#$%',
            'category' => 'Categoría/Especial',
        ];

        $result = self::$orm->table('products')->replaceInto($productWithSpecialChars);

        self::assertSame('success', $result['status']);

        // Verificar que los caracteres especiales se guardaron correctamente
        $inserted = self::$orm->table('products')->where('sku', '=', 'REPLACE-SPECIAL-001')->firstArray();
        self::assertStringContainsString("'con'", $inserted['name']);
        self::assertStringContainsString('"comillas"', $inserted['name']);
        self::assertStringContainsString('ñáéíóú', $inserted['description']);
        self::assertStringContainsString('@#$%', $inserted['description']);
        self::assertSame('Categoría/Especial', $inserted['category']);
    }

    // ======================================================================
    // TESTS DE DIFERENCIAS ENTRE REPLACE INTO VS UPSERT
    // ======================================================================

    public function testReplaceIntoVsUpsertBehavior(): void
    {
        // Test: Demostrar la diferencia entre REPLACE INTO y UPSERT

        // 1. Insertar registro inicial con campos disponibles
        $initialData = [
            'sku' => 'COMPARE-001',
            'name' => 'Producto Inicial',
            'price' => 100.00,
            'stock' => 10,
            'description' => 'Descripción inicial',
            'category' => 'Categoría inicial',
        ];

        self::$orm->table('products')->insert($initialData);

        // 2. Usar UPSERT para actualizar solo algunos campos
        $upsertData = [
            'sku' => 'COMPARE-001',
            'name' => 'Producto Actualizado UPSERT',
            'price' => 150.00,
        ];

        self::$orm->table('products')->upsert($upsertData, ['sku'], ['name', 'price']);

        // Verificar que UPSERT preservó los otros campos
        $afterUpsert = self::$orm->table('products')->where('sku', '=', 'COMPARE-001')->firstArray();
        self::assertSame('Producto Actualizado UPSERT', $afterUpsert['name']);
        self::assertEquals(150.00, (float) $afterUpsert['price']);
        self::assertSame(10, $afterUpsert['stock']); // Preservado
        self::assertSame('Descripción inicial', $afterUpsert['description']); // Preservado
        self::assertSame('Categoría inicial', $afterUpsert['category']); // Preservado

        // 3. Usar REPLACE INTO con los mismos datos parciales
        $replaceData = [
            'sku' => 'COMPARE-001',
            'name' => 'Producto Reemplazado REPLACE',
            'price' => 200.00,
        ];

        self::$orm->table('products')->replaceInto($replaceData);

        // Verificar que REPLACE INTO eliminó los campos no especificados
        $afterReplace = self::$orm->table('products')->where('sku', '=', 'COMPARE-001')->firstArray();
        self::assertSame('Producto Reemplazado REPLACE', $afterReplace['name']);
        self::assertEquals(200.00, (float) $afterReplace['price']);
        self::assertSame(0, $afterReplace['stock']); // Se resetea al valor por defecto (0), no NULL
        self::assertNull($afterReplace['description']); // Se perdió
        self::assertNull($afterReplace['category']); // Se perdió
    }

    // ======================================================================
    // TESTS DE RENDIMIENTO Y CASOS EDGE
    // ======================================================================

    public function testReplaceIntoPerformance(): void
    {
        // Test: Rendimiento con múltiples operaciones REPLACE INTO
        $startTime = microtime(true);

        for ($i = 1; $i <= 20; ++$i) {
            $data = [
                'sku' => 'REPLACE-PERF-' . str_pad((string) $i, 3, '0', STR_PAD_LEFT),
                'name' => "Producto Replace Performance {$i}",
                'price' => 50.00 + $i,
                'stock' => $i * 2,
            ];

            $result = self::$orm->table('products')->replaceInto($data);
            self::assertSame('success', $result['status']);
        }

        $endTime = microtime(true);
        $executionTime = $endTime - $startTime;

        // Verificar que todas las operaciones fueron exitosas
        $count = self::$orm->table('products')
            ->where('sku', 'LIKE', 'REPLACE-PERF-%')
            ->count()
        ;

        self::assertSame(20, $count);

        // El tiempo debe ser razonable (menos de 3 segundos para 20 operaciones)
        self::assertLessThan(
            3.0,
            $executionTime,
            "20 operaciones replaceInto tomaron demasiado tiempo: {$executionTime}s",
        );
    }

    public function testReplaceIntoWithLargeData(): void
    {
        // Test: REPLACE INTO con datos grandes
        $largeDescription = str_repeat('Este es un texto muy largo para probar el manejo de datos grandes. ', 100);

        $largeDataProduct = [
            'sku' => 'REPLACE-LARGE-001',
            'name' => 'Producto con Datos Grandes',
            'price' => 999.99,
            'stock' => 1,
            'description' => $largeDescription,
        ];

        $result = self::$orm->table('products')->replaceInto($largeDataProduct);

        self::assertSame('success', $result['status']);

        // Verificar que los datos grandes se guardaron correctamente
        $inserted = self::$orm->table('products')->where('sku', '=', 'REPLACE-LARGE-001')->firstArray();
        self::assertSame('Producto con Datos Grandes', $inserted['name']);
        self::assertSame($largeDescription, $inserted['description']);
        self::assertGreaterThan(5000, strlen($inserted['description']));
    }

    public function testReplaceIntoIdempotency(): void
    {
        // Test: REPLACE INTO debe ser idempotente
        $productData = [
            'sku' => 'REPLACE-IDEM-001',
            'name' => 'Producto Idempotente',
            'price' => 300.00,
            'stock' => 15,
        ];

        // Primera operación
        $result1 = self::$orm->table('products')->replaceInto($productData);
        self::assertSame('success', $result1['status']);

        $first = self::$orm->table('products')->where('sku', '=', 'REPLACE-IDEM-001')->firstArray();

        // Segunda operación con los mismos datos
        $result2 = self::$orm->table('products')->replaceInto($productData);
        self::assertSame('success', $result2['status']);

        $second = self::$orm->table('products')->where('sku', '=', 'REPLACE-IDEM-001')->firstArray();

        // Los resultados deben ser idénticos
        self::assertSame($first['name'], $second['name']);
        self::assertEquals((float) $first['price'], (float) $second['price']);
        self::assertSame($first['stock'], $second['stock']);

        // Debe seguir habiendo solo un registro
        $count = self::$orm->table('products')->where('sku', '=', 'REPLACE-IDEM-001')->count();
        self::assertSame(1, $count);
    }

    public function testReplaceIntoWithInvalidColumnName(): void
    {
        // Test: REPLACE INTO debe validar nombres de columnas
        $this->expectException(VersaORMException::class);

        $invalidData = [
            'sku' => 'REPLACE-INVALID-001',
            'name' => 'Test',
            'invalid--column' => 'value', // Nombre de columna inválido
        ];

        self::$orm->table('products')->replaceInto($invalidData);
    }

    // ======================================================================
    // TESTS DE INTEGRACIÓN CON VersaModel
    // ======================================================================

    public function testReplaceIntoWithVersaModel(): void
    {
        // Test: REPLACE INTO debe funcionar con VersaModel
        $product = new VersaModel('products', self::$orm);
        $product->sku = 'REPLACE-MODEL-001';
        $product->name = 'Producto desde VersaModel';
        $product->price = 450.00;
        $product->stock = 30;

        // VersaModel debería tener acceso al método replaceInto
        $data = [
            'sku' => $product->sku,
            'name' => $product->name,
            'price' => $product->price,
            'stock' => $product->stock,
        ];

        $result = self::$orm->table('products')->replaceInto($data);
        self::assertSame('success', $result['status']);

        // Verificar que se guardó correctamente
        $saved = self::$orm->table('products')->where('sku', '=', 'REPLACE-MODEL-001')->firstArray();
        self::assertSame('Producto desde VersaModel', $saved['name']);
        self::assertEquals(450.00, (float) $saved['price']);
    }
}
