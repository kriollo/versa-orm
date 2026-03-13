<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Modelo de prueba con fillable configurado.
 */
class TestProduct extends VersaModel
{
    protected array $fillable = ['name', 'price', 'stock', 'active', 'category'];
}

/**
 * Tests avanzados para VersaModel - Métodos menos cubiertos.
 */
class VersaModelAdvancedTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]);

        VersaModel::setORM($this->orm);

        // Crear tablas de prueba
        $this->orm->exec(
            'CREATE TABLE products (id INTEGER PRIMARY KEY, name VARCHAR, price REAL, stock INTEGER, active BOOLEAN)',
        );
        $this->orm->exec('CREATE TABLE categories (id INTEGER PRIMARY KEY, name VARCHAR)');

        // Insertar datos de prueba
        $this->orm->exec('INSERT INTO products (name, price, stock, active) VALUES (?, ?, ?, ?)', [
            'Laptop',
            999.99,
            10,
            1,
        ]);
        $this->orm->exec('INSERT INTO products (name, price, stock, active) VALUES (?, ?, ?, ?)', [
            'Mouse',
            29.99,
            50,
            1,
        ]);
        $this->orm->exec('INSERT INTO products (name, price, stock, active) VALUES (?, ?, ?, ?)', [
            'Keyboard',
            79.99,
            0,
            0,
        ]);
    }

    /**
     * Prueba exportAll - convertir array de modelos a arrays.
     */
    public function testExportAll(): void
    {
        $products = VersaModel::findAll('products', 'active = ?', [1]);
        $exported = VersaModel::exportAll($products);

        static::assertIsArray($exported);
        static::assertCount(2, $exported);
        static::assertArrayHasKey('name', $exported[0]);
        static::assertSame('Laptop', $exported[0]['name']);
    }

    /**
     * Prueba count estático.
     */
    public function testCountStatic(): void
    {
        $count = VersaModel::count('products', 'active = ?', [1]);
        static::assertSame(2, $count);

        $totalCount = VersaModel::count('products');
        static::assertSame(3, $totalCount);
    }

    /**
     * Prueba storeAll - guardar múltiples modelos.
     */
    public function testStoreAll(): void
    {
        $product1 = VersaModel::dispense('products');
        $product1->name = 'Monitor';
        $product1->price = 199.99;
        $product1->stock = 5;
        $product1->active = 1;

        $product2 = VersaModel::dispense('products');
        $product2->name = 'Webcam';
        $product2->price = 49.99;
        $product2->stock = 20;
        $product2->active = 1;

        $results = VersaModel::storeAll([$product1, $product2]);

        static::assertCount(2, $results);
        static::assertNotNull($product1->id);
        static::assertNotNull($product2->id);
    }

    /**
     * Prueba trashAll - eliminar múltiples modelos.
     */
    public function testTrashAll(): void
    {
        $products = VersaModel::findAll('products', 'active = ?', [0]);
        static::assertCount(1, $products);

        VersaModel::trashAll($products);

        $remainingCount = VersaModel::count('products');
        static::assertSame(2, $remainingCount);
    }

    /**
     * Prueba fresh - recargar modelo desde BD.
     */
    public function testFresh(): void
    {
        $product = VersaModel::load('products', 1);
        $originalPrice = $product->price;

        // Modificar directamente en BD
        $this->orm->exec('UPDATE products SET price = ? WHERE id = ?', [1299.99, 1]);

        // Recargar - fresh devuelve una nueva instancia
        $freshProduct = $product->fresh();

        static::assertNotEquals($originalPrice, $freshProduct->price);
        static::assertSame(1299.99, $freshProduct->price);
    }

    /**
     * Prueba verificar si modelo tiene ID (está guardado).
     */
    public function testHasId(): void
    {
        $product = VersaModel::load('products', 1);
        static::assertNotNull($product->id);

        $newProduct = VersaModel::dispense('products');
        static::assertNull($newProduct->id);
    }

    /**
     * Prueba getAttribute - obtener atributos del modelo.
     */
    public function testGetAttribute(): void
    {
        $product = VersaModel::load('products', 1);

        $name = $product->getAttribute('name');
        static::assertSame('Laptop', $name);

        $price = $product->getAttribute('price');
        static::assertSame(999.99, $price);
    }

    /**
     * Prueba modificación de atributos.
     */
    public function testAttributeModification(): void
    {
        $product = VersaModel::load('products', 1);
        static::assertSame('Laptop', $product->getAttribute('name'));

        $product->name = 'Modified Name';

        // Verificar con getAttribute que evita cache
        $product->store();
        $reloaded = VersaModel::load('products', 1);
        static::assertSame('Modified Name', $reloaded->getAttribute('name'));
    }

    /**
     * Prueba export para obtener datos actuales.
     */
    public function testExportCurrent(): void
    {
        $product = VersaModel::load('products', 1);
        $original = $product->export();
        static::assertSame('Laptop', $original['name']);

        $product->name = 'New Name';
        $product->store();

        // Recargar para obtener datos frescos
        $reloaded = VersaModel::load('products', 1);
        $updated = $reloaded->export();

        static::assertSame('New Name', $updated['name']);
    }

    /**
     * Prueba fill - llenar modelo con array de datos.
     */
    public function testFill(): void
    {
        $product = new TestProduct('products', $this->orm);
        $product->fill([
            'name' => 'Headphones',
            'price' => 59.99,
            'stock' => 30,
            'active' => 1,
        ]);

        static::assertSame('Headphones', $product->name);
        static::assertSame(59.99, $product->price);
        static::assertSame(30, $product->stock);
    }

    /**
     * Prueba export y extracción de campos específicos.
     */
    public function testExportSpecificFields(): void
    {
        $product = VersaModel::load('products', 1);
        $data = $product->export();
        $subset = array_intersect_key($data, array_flip(['name', 'price']));

        static::assertIsArray($subset);
        static::assertArrayHasKey('name', $subset);
        static::assertArrayHasKey('price', $subset);
        static::assertArrayNotHasKey('stock', $subset);
    }

    /**
     * Prueba export con exclusión de campos.
     */
    public function testExportExcludeFields(): void
    {
        $product = VersaModel::load('products', 1);
        $data = $product->export();
        $filtered = array_diff_key($data, array_flip(['stock', 'active']));

        static::assertIsArray($filtered);
        static::assertArrayHasKey('name', $filtered);
        static::assertArrayHasKey('price', $filtered);
        static::assertArrayNotHasKey('stock', $filtered);
        static::assertArrayNotHasKey('active', $filtered);
    }

    /**
     * Prueba duplicación de modelo mediante dispense.
     */
    public function testDuplicateModel(): void
    {
        $product = VersaModel::load('products', 1);
        $data = $product->export();

        $replica = VersaModel::dispense('products');
        $replica->name = $data['name'];
        $replica->price = $data['price'];
        $replica->stock = $data['stock'];

        static::assertNull($replica->id);
        static::assertEquals($product->name, $replica->name);
        static::assertEquals($product->price, $replica->price);
    }

    /**
     * Prueba serialización JSON mediante export.
     */
    public function testJsonSerialization(): void
    {
        $product = VersaModel::load('products', 1);
        $json = json_encode($product->export());

        static::assertIsString($json);
        $decoded = json_decode($json, true);
        static::assertIsArray($decoded);
        static::assertSame('Laptop', $decoded['name']);
    }

    /**
     * Prueba modificación numérica de atributos.
     */
    public function testNumericModification(): void
    {
        $product = VersaModel::load('products', 1);

        $product->stock = 20;
        $product->store();

        $reloaded = VersaModel::load('products', 1);
        static::assertSame(20, (int) $reloaded->stock);

        $reloaded->stock = 15;
        $reloaded->store();

        $final = VersaModel::load('products', 1);
        static::assertSame(15, (int) $final->stock);
    }

    /**
     * Prueba whereHas - consulta con relación.
     */
    public function testWhereHas(): void
    {
        // Crear productos con categoría
        $this->orm->exec('INSERT INTO categories (name) VALUES (?)', ['Electronics']);

        $products = $this->orm
            ->table('products')
            ->where('active', '=', 1)
            ->get();

        static::assertGreaterThan(0, count($products));
    }

    /**
     * Prueba create estático - crear instancia sin guardar.
     */
    public function testCreateStatic(): void
    {
        $product = new TestProduct('products', $this->orm);
        $product->fill([
            'name' => 'Speaker',
            'price' => 89.99,
            'stock' => 15,
            'active' => 1,
        ]);

        static::assertSame('Speaker', $product->name);
        static::assertSame(89.99, $product->price);

        // No debería tener ID hasta que se guarde
        static::assertNull($product->id);
    }

    /**
     * Prueba findOne - buscar por ID.
     */
    public function testFindOne(): void
    {
        $product = VersaModel::findOne('products', 1);

        static::assertNotNull($product);
        static::assertSame('Laptop', $product->name);
        static::assertNotNull($product->id);
    }

    /**
     * Prueba findAll - buscar con condiciones.
     */
    public function testFindAll(): void
    {
        $products = VersaModel::findAll('products', 'active = ?', [1]);

        static::assertIsArray($products);
        static::assertSame(2, count($products));
        static::assertSame('Laptop', $products[0]->name);
    }
}
