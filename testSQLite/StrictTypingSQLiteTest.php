<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaModel;

require_once __DIR__ . '/TestCase.php';

/**
 * Tests exhaustivos de tipado estricto para SQLite.
 * SQLite tiene un sistema de tipos más permisivo, estos tests verifican
 * que el ORM mantenga la integridad de tipos a pesar de las limitaciones de SQLite.
 *
 * @group sqlite
 * @group typing
 * @group strict
 */
class StrictTypingSQLiteTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Drop test tables to ensure clean state
        self::$orm->schemaDrop('test_int_limits');
        self::$orm->schemaDrop('test_json');
    }

    /**
     * Test: INTEGER affinity en SQLite.
     */
    public function test_integer_affinity_sqlite(): void
    {
        self::$orm->schemaCreate('test_integers', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'value', 'type' => 'INTEGER'],
        ]);

        $model = VersaModel::dispense('test_integers');
        $model->value = 42;
        $model->store();

        $loaded = VersaModel::load('test_integers', $model->id);
        static::assertIsInt($loaded->value);
        static::assertSame(42, $loaded->value);

        // SQLite permite guardar strings en columnas INTEGER
        $model2 = VersaModel::dispense('test_integers');
        $model2->value = '123';
        $model2->store();

        $loaded2 = VersaModel::load('test_integers', $model2->id);
        // El ORM debe convertir a int
        static::assertIsInt($loaded2->value);
        static::assertSame(123, $loaded2->value);

        self::$orm->schemaDrop('test_integers');
    }

    /**
     * Test: TEXT affinity con diferentes tipos de strings.
     */
    public function test_text_affinity_sqlite(): void
    {
        self::$orm->schemaCreate('test_text', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'content', 'type' => 'TEXT'],
        ]);

        // String normal
        $model = VersaModel::dispense('test_text');
        $model->content = 'Hello World';
        $model->store();

        $loaded = VersaModel::load('test_text', $model->id);
        static::assertIsString($loaded->content);
        static::assertSame('Hello World', $loaded->content);

        // String vacío
        $model2 = VersaModel::dispense('test_text');
        $model2->content = '';
        $model2->store();

        $loaded2 = VersaModel::load('test_text', $model2->id);
        static::assertSame('', $loaded2->content);

        // String con Unicode
        $model3 = VersaModel::dispense('test_text');
        $model3->content = '你好世界 🌍';
        $model3->store();

        $loaded3 = VersaModel::load('test_text', $model3->id);
        static::assertStringContainsString('🌍', $loaded3->content);

        self::$orm->schemaDrop('test_text');
    }

    /**
     * Test: REAL affinity (floating point).
     */
    public function test_real_affinity_sqlite(): void
    {
        self::$orm->schemaCreate('test_real', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'value', 'type' => 'REAL'],
        ]);

        $model = VersaModel::dispense('test_real');
        $model->value = 3.14159;
        $model->store();

        $loaded = VersaModel::load('test_real', $model->id);
        static::assertIsFloat($loaded->value);
        static::assertEqualsWithDelta(3.14159, $loaded->value, 0.00001);

        // Valor muy pequeño
        $model2 = VersaModel::dispense('test_real');
        $model2->value = 0.00000001;
        $model2->store();

        $loaded2 = VersaModel::load('test_real', $model2->id);
        static::assertIsFloat($loaded2->value);

        self::$orm->schemaDrop('test_real');
    }

    /**
     * Test: BLOB affinity (datos binarios).
     */
    public function test_blob_affinity_sqlite(): void
    {
        self::$orm->schemaCreate('test_blob', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'data', 'type' => 'BLOB'],
        ]);

        $binaryData = pack('H*', '48656c6c6f'); // "Hello" en hexadecimal

        $model = VersaModel::dispense('test_blob');
        $model->data = $binaryData;
        $model->store();

        $loaded = VersaModel::load('test_blob', $model->id);
        static::assertSame($binaryData, $loaded->data);

        self::$orm->schemaDrop('test_blob');
    }

    /**
     * Test: NUMERIC affinity (puede almacenar INTEGER o REAL).
     */
    public function test_numeric_affinity_sqlite(): void
    {
        self::$orm->schemaCreate('test_numeric', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'value', 'type' => 'NUMERIC'],
        ]);

        // Integer
        $model = VersaModel::dispense('test_numeric');
        $model->value = 100;
        $model->store();

        $loaded = VersaModel::load('test_numeric', $model->id);
        static::assertTrue(is_int($loaded->value) || is_float($loaded->value));

        // Float
        $model2 = VersaModel::dispense('test_numeric');
        $model2->value = 99.99;
        $model2->store();

        $loaded2 = VersaModel::load('test_numeric', $model2->id);
        static::assertTrue(is_int($loaded2->value) || is_float($loaded2->value));

        self::$orm->schemaDrop('test_numeric');
    }

    /**
     * Test: Conversión de tipos en SQLite (permisividad).
     */
    public function test_type_conversion_permissiveness(): void
    {
        self::$orm->schemaCreate('test_conversion', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'int_col', 'type' => 'INTEGER'],
            ['name' => 'text_col', 'type' => 'TEXT'],
        ]);

        // Guardar número en columna TEXT
        $model = VersaModel::dispense('test_conversion');
        $model->int_col = 42;
        $model->text_col = 999;
        $model->store();

        $loaded = VersaModel::load('test_conversion', $model->id);
        static::assertIsInt($loaded->int_col);
        static::assertIsString($loaded->text_col);
        static::assertSame('999', $loaded->text_col);

        self::$orm->schemaDrop('test_conversion');
    }

    /**
     * Test: NULL handling en diferentes tipos.
     */
    public function test_null_handling_across_types(): void
    {
        self::$orm->schemaCreate('test_nulls', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'int_val', 'type' => 'INTEGER', 'nullable' => true],
            ['name' => 'text_val', 'type' => 'TEXT', 'nullable' => true],
            ['name' => 'real_val', 'type' => 'REAL', 'nullable' => true],
        ]);

        $model = VersaModel::dispense('test_nulls');
        $model->int_val = null;
        $model->text_val = null;
        $model->real_val = null;
        $model->store();

        $loaded = VersaModel::load('test_nulls', $model->id);
        static::assertNull($loaded->int_val);
        static::assertNull($loaded->text_val);
        static::assertNull($loaded->real_val);

        self::$orm->schemaDrop('test_nulls');
    }

    /**
     * Test: Límites de INTEGER en SQLite (64-bit signed).
     */
    public function test_integer_limits_sqlite(): void
    {
        self::$orm->schemaCreate('test_int_limits', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'value', 'type' => 'INTEGER'],
        ]);

        // Máximo valor positivo (64-bit)
        $model = VersaModel::dispense('test_int_limits');
        $model->value = 9223372036854775807;
        $model->store();

        $loaded = VersaModel::load('test_int_limits', $model->id);
        static::assertSame(9223372036854775807, $loaded->value);

        // Valores grandes negativos - usar un valor más seguro que PHP_INT_MIN
        // PHP_INT_MIN puede causar overflow en PDO/SQLite
        $model2 = VersaModel::dispense('test_int_limits');
        $largeNegative = -9223372036854775807; // Slightly less extreme than PHP_INT_MIN
        $model2->value = $largeNegative;
        $model2->store();

        $loaded2 = VersaModel::load('test_int_limits', $model2->id);
        static::assertSame($largeNegative, $loaded2->value);

        self::$orm->schemaDrop('test_int_limits');
    }

    /**
     * Test: Manejo de strings muy largos (SQLite no tiene límite de VARCHAR).
     */
    public function test_very_long_strings(): void
    {
        self::$orm->schemaCreate('test_long_strings', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'content', 'type' => 'TEXT'],
        ]);

        // String de 1MB
        $longString = str_repeat('A', 1024 * 1024);

        $model = VersaModel::dispense('test_long_strings');
        $model->content = $longString;
        $model->store();

        $loaded = VersaModel::load('test_long_strings', $model->id);
        static::assertSame(1024 * 1024, strlen($loaded->content));
        static::assertSame($longString, $loaded->content);

        self::$orm->schemaDrop('test_long_strings');
    }

    /**
     * Test: JSON storage en SQLite (como TEXT).
     */
    public function test_json_storage_as_text(): void
    {
        self::$orm->schemaCreate('test_json', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'data', 'type' => 'TEXT'], // SQLite no tiene JSON nativo
        ]);

        $jsonData = ['name' => 'Test', 'value' => 42, 'nested' => ['key' => 'value']];

        $model = VersaModel::dispense('test_json');
        $model->data = json_encode($jsonData);
        $model->store();

        $loaded = VersaModel::load('test_json', $model->id);
        $decoded = json_decode($loaded->data, true);

        static::assertIsArray($decoded);
        static::assertSame('Test', $decoded['name']);
        static::assertSame(42, $decoded['value']);
        static::assertArrayHasKey('nested', $decoded);

        self::$orm->schemaDrop('test_json');
    }

    /**
     * Test: Boolean storage en SQLite (como INTEGER 0/1).
     */
    public function test_boolean_storage_as_integer(): void
    {
        self::$orm->schemaCreate('test_boolean', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'active', 'type' => 'INTEGER'], // SQLite no tiene BOOLEAN
        ]);

        $model = VersaModel::dispense('test_boolean');
        $model->active = 1; // true
        $model->store();

        $loaded = VersaModel::load('test_boolean', $model->id);
        static::assertSame(1, $loaded->active);

        $model2 = VersaModel::dispense('test_boolean');
        $model2->active = 0; // false
        $model2->store();

        $loaded2 = VersaModel::load('test_boolean', $model2->id);
        static::assertSame(0, $loaded2->active);

        self::$orm->schemaDrop('test_boolean');
    }

    /**
     * Test: Date/Time storage en SQLite (como TEXT o INTEGER).
     */
    public function test_datetime_storage_sqlite(): void
    {
        self::$orm->schemaCreate('test_datetime', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'created_at', 'type' => 'TEXT'], // ISO8601 string
        ]);

        $now = date('Y-m-d H:i:s');

        $model = VersaModel::dispense('test_datetime');
        $model->created_at = $now;
        $model->store();

        $loaded = VersaModel::load('test_datetime', $model->id);
        static::assertIsString($loaded->created_at);
        static::assertStringContainsString(date('Y-m-d'), $loaded->created_at);

        self::$orm->schemaDrop('test_datetime');
    }

    /**
     * Test: Zero y empty string handling.
     */
    public function test_zero_and_empty_values(): void
    {
        self::$orm->schemaCreate('test_zero_empty', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'int_val', 'type' => 'INTEGER'],
            ['name' => 'text_val', 'type' => 'TEXT'],
        ]);

        // Cero no es NULL
        $model = VersaModel::dispense('test_zero_empty');
        $model->int_val = 0;
        $model->text_val = '';
        $model->store();

        $loaded = VersaModel::load('test_zero_empty', $model->id);
        static::assertSame(0, $loaded->int_val);
        static::assertSame('', $loaded->text_val);
        static::assertNotNull($loaded->int_val);
        static::assertNotNull($loaded->text_val);

        self::$orm->schemaDrop('test_zero_empty');
    }

    /**
     * Test: Caracteres especiales y escape en SQLite.
     */
    public function test_special_characters_escaping_sqlite(): void
    {
        self::$orm->schemaCreate('test_escape', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
            ['name' => 'content', 'type' => 'TEXT'],
        ]);

        // SQL injection attempt
        $model = VersaModel::dispense('test_escape');
        $model->content = "'; DROP TABLE test_escape; --";
        $model->store();

        $loaded = VersaModel::load('test_escape', $model->id);
        static::assertSame("'; DROP TABLE test_escape; --", $loaded->content);

        // Comillas simples y dobles
        $model2 = VersaModel::dispense('test_escape');
        $model2->content = "It's a \"test\" string";
        $model2->store();

        $loaded2 = VersaModel::load('test_escape', $model2->id);
        static::assertStringContainsString("It's", $loaded2->content);
        static::assertStringContainsString('"test"', $loaded2->content);

        self::$orm->schemaDrop('test_escape');
    }
}
