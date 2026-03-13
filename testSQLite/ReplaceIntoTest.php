<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaModel;

/**
 * Test unitarios para operaciones REPLACE INTO en SQLite.
 *
 * En SQLite, replaceInto se emula mediante UPSERT, por lo que NO elimina
 * el registro previo, sino que actualiza los valores existentes.
 * Esto difiere del comportamiento nativo de REPLACE en MySQL.
 *
 * @group sqlite
 */
class ReplaceIntoTest extends TestCase
{
    public function test_replace_into_new_record(): void
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

        static::assertSame('success', $result['status']);

        // Verificar que se insertó correctamente
        $inserted = self::$orm->table('products')->where('sku', '=', 'REPLACE-NEW-001')->firstArray();
        static::assertNotNull($inserted);
        static::assertSame('Producto Replace Nuevo', $inserted['name']);
        static::assertSame(199.99, (float) $inserted['price']);
    }

    public function test_replace_into_existing_record_preserves_missing_columns(): void
    {
        // Test: REPLACE INTO en SQLite (emulado) debe actualizar y PRESERVAR columnas no especificadas

        // Insertar un registro inicial
        $initialProduct = [
            'sku' => 'REPLACE-EXIST-001',
            'name' => 'Producto Original',
            'price' => 100.00,
            'stock' => 10,
            'description' => 'Descripción original que debe conservarse', // Columna extra
        ];

        self::$orm->table('products')->insert($initialProduct);

        // Usar REPLACE INTO con menos columnas
        $replacementProduct = [
            'sku' => 'REPLACE-EXIST-001', // Misma clave única
            'name' => 'Producto Reemplazado',
            'price' => 250.00,
            // stock y description NO se incluyen
        ];

        $result = self::$orm->table('products')->replaceInto($replacementProduct);

        static::assertSame('success', $result['status']);

        $updated = self::$orm->table('products')->where('sku', '=', 'REPLACE-EXIST-001')->firstArray();
        static::assertNotNull($updated);

        // Valores actualizados
        static::assertSame('Producto Reemplazado', $updated['name']);
        static::assertSame(250.00, (float) $updated['price']);

        // Valores PRESERVADOS (diferencia clave con MySQL REPLACE)
        static::assertSame(10, $updated['stock']);
        static::assertSame('Descripción original que debe conservarse', $updated['description']);
    }

    public function test_replace_into_with_versamodel(): void
    {
        $product = new VersaModel('products', self::$orm);
        $product->sku = 'REPLACE-MODEL-001';
        $product->name = 'Producto VersaModel';
        $product->price = 50.00;

        // Guardar inicial
        $product->store();

        // Modificar para replace
        $data = [
            'sku' => 'REPLACE-MODEL-001',
            'name' => 'Producto VersaModel Updated',
            'price' => 75.00,
        ];

        $result = self::$orm->table('products')->replaceInto($data);
        static::assertSame('success', $result['status']);

        $saved = self::$orm->table('products')->where('sku', '=', 'REPLACE-MODEL-001')->findOne();
        static::assertSame('Producto VersaModel Updated', $saved->name);
        static::assertSame(75.00, (float) $saved->price);
    }
}
