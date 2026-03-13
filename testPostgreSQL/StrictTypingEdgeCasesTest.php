<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;
use VersaORM\VersaORMException;

require_once __DIR__ . '/TestCase.php';

/**
 * Tests exhaustivos para el sistema de tipado estricto - Edge Cases y validación rigurosa.
 *
 * @group postgresql
 * @group typing
 * @group strict
 */
class StrictTypingEdgeCasesTest extends TestCase
{
    /**
     * Clean up any leftover test tables before each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Drop any leftover test tables from previous runs
        $tables = [
            'test_integers',
            'test_bigints',
            'test_decimals',
            'test_floats',
            'test_booleans',
            'test_varchars',
            'test_texts',
            'test_jsons',
            'test_timestamps',
            'test_nullables',
            'test_coercion',
            'test_mixed',
        ];

        foreach ($tables as $table) {
            try {
                self::$orm->schemaDrop($table);
            } catch (VersaORMException $e) {
                // Table doesn't exist, ignore
            }
        }
    }

    /**
     * Test: Validación de INTEGER con valores límite.
     */
    public function test_integer_boundary_values(): void
    {
        // INT32 Max
        self::$orm->schemaCreate('test_integers', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'value', 'type' => 'INTEGER'],
        ]);

        $model = VersaModel::dispense('test_integers');
        $model->value = 2147483647; // INT32_MAX
        $model->store();

        $loaded = VersaModel::load('test_integers', $model->id);
        static::assertSame(2147483647, $loaded->value);
        static::assertIsInt($loaded->value);

        // INT32 Min
        $model2 = VersaModel::dispense('test_integers');
        $model2->value = -2147483648; // INT32_MIN
        $model2->store();

        $loaded2 = VersaModel::load('test_integers', $model2->id);
        static::assertSame(-2147483648, $loaded2->value);

        // Valor cero
        $model3 = VersaModel::dispense('test_integers');
        $model3->value = 0;
        $model3->store();

        $loaded3 = VersaModel::load('test_integers', $model3->id);
        static::assertSame(0, $loaded3->value);

        self::$orm->schemaDrop('test_integers');
    }

    /**
     * Test: Validación de BIGINT con valores muy grandes.
     */
    public function test_bigint_large_values(): void
    {
        self::$orm->schemaCreate('test_bigints', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'value', 'type' => 'BIGINT'],
        ]);

        $model = VersaModel::dispense('test_bigints');
        $model->value = 9223372036854775807; // PHP_INT_MAX en 64 bits
        $model->store();

        $loaded = VersaModel::load('test_bigints', $model->id);
        static::assertSame(9223372036854775807, $loaded->value);
        static::assertIsInt($loaded->value);

        // Valor negativo muy grande
        $model2 = VersaModel::dispense('test_bigints');
        $model2->value = PHP_INT_MIN; // -9223372036854775808 on 64-bit
        $model2->store();

        $loaded2 = VersaModel::load('test_bigints', $model2->id);
        static::assertSame(PHP_INT_MIN, $loaded2->value);

        self::$orm->schemaDrop('test_bigints');
    }

    /**
     * Test: DECIMAL y NUMERIC con precisión extrema.
     */
    public function test_decimal_precision_edge_cases(): void
    {
        self::$orm->schemaCreate('test_decimals', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'price', 'type' => 'DECIMAL(20,10)'],
            ['name' => 'small_value', 'type' => 'DECIMAL(5,4)'],
        ]);

        // Valor con máxima precisión
        $model = VersaModel::dispense('test_decimals');
        $model->price = '1234567890.9876543210';
        $model->small_value = '9.9999';
        $model->store();

        $loaded = VersaModel::load('test_decimals', $model->id);
        static::assertIsString($loaded->price);
        static::assertSame('1234567890.9876543210', $loaded->price);
        static::assertSame('9.9999', $loaded->small_value);

        // Valores muy pequeños
        $model2 = VersaModel::dispense('test_decimals');
        $model2->price = '0.0000000001';
        $model2->small_value = '0.0001';
        $model2->store();

        $loaded2 = VersaModel::load('test_decimals', $model2->id);
        static::assertSame('0.0000000001', $loaded2->price);

        // Valor cero exacto
        $model3 = VersaModel::dispense('test_decimals');
        $model3->price = '0.0000000000';
        $model3->store();

        $loaded3 = VersaModel::load('test_decimals', $model3->id);
        static::assertSame('0.0000000000', $loaded3->price);

        self::$orm->schemaDrop('test_decimals');
    }

    /**
     * Test: FLOAT y DOUBLE con valores especiales.
     */
    public function test_float_special_values(): void
    {
        self::$orm->schemaCreate('test_floats', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'value', 'type' => 'DOUBLE PRECISION'],
        ]);

        // Valor muy grande
        $model = VersaModel::dispense('test_floats');
        $model->value = 1.7976931348623157E+308; // Cerca del máximo
        $model->store();

        $loaded = VersaModel::load('test_floats', $model->id);
        static::assertIsFloat($loaded->value);
        static::assertGreaterThan(1E+308, $loaded->value);

        // Valor muy pequeño positivo
        $model2 = VersaModel::dispense('test_floats');
        $model2->value = 2.2250738585072014E-308;
        $model2->store();

        $loaded2 = VersaModel::load('test_floats', $model2->id);
        static::assertIsFloat($loaded2->value);

        // Cero flotante
        $model3 = VersaModel::dispense('test_floats');
        $model3->value = 0.0;
        $model3->store();

        $loaded3 = VersaModel::load('test_floats', $model3->id);
        static::assertSame(0.0, $loaded3->value);

        // Valor negativo
        $model4 = VersaModel::dispense('test_floats');
        $model4->value = -123.456789;
        $model4->store();

        $loaded4 = VersaModel::load('test_floats', $model4->id);
        static::assertIsFloat($loaded4->value);
        static::assertLessThan(0, $loaded4->value);

        self::$orm->schemaDrop('test_floats');
    }

    /**
     * Test: BOOLEAN con valores truthy/falsy.
     */
    public function test_boolean_strict_values(): void
    {
        self::$orm->schemaCreate('test_booleans', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'active', 'type' => 'BOOLEAN'],
            ['name' => 'verified', 'type' => 'BOOLEAN'],
        ]);

        // True explícito
        $model = VersaModel::dispense('test_booleans');
        $model->active = true;
        $model->verified = false;
        $model->store();

        $loaded = VersaModel::load('test_booleans', $model->id);
        static::assertIsBool($loaded->active);
        static::assertIsBool($loaded->verified);
        static::assertTrue($loaded->active);
        static::assertFalse($loaded->verified);

        // Valores numéricos (1 = true, 0 = false)
        $model2 = VersaModel::dispense('test_booleans');
        $model2->active = 1;
        $model2->verified = 0;
        $model2->store();

        $loaded2 = VersaModel::load('test_booleans', $model2->id);
        static::assertIsBool($loaded2->active);
        static::assertIsBool($loaded2->verified);
        static::assertTrue($loaded2->active);
        static::assertFalse($loaded2->verified);

        self::$orm->schemaDrop('test_booleans');
    }

    /**
     * Test: VARCHAR con límites de longitud exactos.
     */
    public function test_varchar_length_boundaries(): void
    {
        self::$orm->schemaCreate('test_varchars', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'short', 'type' => 'VARCHAR(10)'],
            ['name' => 'medium', 'type' => 'VARCHAR(255)'],
            ['name' => 'long', 'type' => 'VARCHAR(1000)'],
        ]);

        // Exactamente el límite
        $model = VersaModel::dispense('test_varchars');
        $model->short = '1234567890'; // Exacto 10 chars
        $model->medium = str_repeat('A', 255); // Exacto 255 chars
        $model->long = str_repeat('B', 1000); // Exacto 1000 chars
        $model->store();

        $loaded = VersaModel::load('test_varchars', $model->id);
        static::assertSame(10, strlen($loaded->short));
        static::assertSame(255, strlen($loaded->medium));
        static::assertSame(1000, strlen($loaded->long));

        // String vacío
        $model2 = VersaModel::dispense('test_varchars');
        $model2->short = '';
        $model2->medium = '';
        $model2->store();

        $loaded2 = VersaModel::load('test_varchars', $model2->id);
        static::assertSame('', $loaded2->short);
        static::assertSame('', $loaded2->medium);

        // Un solo carácter
        $model3 = VersaModel::dispense('test_varchars');
        $model3->short = 'X';
        $model3->store();

        $loaded3 = VersaModel::load('test_varchars', $model3->id);
        static::assertSame('X', $loaded3->short);

        self::$orm->schemaDrop('test_varchars');
    }

    /**
     * Test: TEXT con contenido masivo.
     */
    public function test_text_large_content(): void
    {
        self::$orm->schemaCreate('test_texts', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'content', 'type' => 'TEXT'],
        ]);

        // Texto muy grande (1 MB)
        $largeText = str_repeat('Lorem ipsum dolor sit amet. ', 36408); // ~1MB
        $model = VersaModel::dispense('test_texts');
        $model->content = $largeText;
        $model->store();

        $loaded = VersaModel::load('test_texts', $model->id);
        static::assertGreaterThan(1000000, strlen($loaded->content));
        static::assertSame($largeText, $loaded->content);

        // Texto con caracteres especiales y Unicode
        $model2 = VersaModel::dispense('test_texts');
        $model2->content = "Hello 世界 🌍 \n\r\t Special: <>{}[]()&*%$#@!";
        $model2->store();

        $loaded2 = VersaModel::load('test_texts', $model2->id);
        static::assertStringContainsString('世界', $loaded2->content);
        static::assertStringContainsString('🌍', $loaded2->content);

        self::$orm->schemaDrop('test_texts');
    }

    /**
     * Test: JSON con estructuras complejas y anidadas.
     */
    public function test_json_complex_structures(): void
    {
        self::$orm->schemaCreate('test_jsons', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'data', 'type' => 'JSON'],
        ]);

        // JSON profundamente anidado
        $complexJson = [
            'level1' => [
                'level2' => [
                    'level3' => [
                        'level4' => [
                            'level5' => [
                                'value' => 'deep nested value',
                                'number' => 42,
                                'array' => [1, 2, 3, 4, 5],
                            ],
                        ],
                    ],
                ],
            ],
            'types' => [
                'null' => null,
                'boolean' => true,
                'integer' => 123,
                'float' => 45.67,
                'string' => 'text',
                'array' => [1, 2, 3],
                'object' => ['key' => 'value'],
            ],
            'unicode' => '日本語 中文 한국어 العربية',
            'special_chars' => "Line\nBreak\tTab\"Quote'Apostrophe",
        ];

        $model = VersaModel::dispense('test_jsons');
        $model->data = $complexJson;
        $model->store();

        $loaded = VersaModel::load('test_jsons', $model->id);
        static::assertIsArray($loaded->data);
        static::assertSame(
            'deep nested value',
            $loaded->data['level1']['level2']['level3']['level4']['level5']['value'],
        );
        static::assertNull($loaded->data['types']['null']);
        static::assertTrue($loaded->data['types']['boolean']);
        static::assertSame(123, $loaded->data['types']['integer']);

        // Array vacío
        $model2 = VersaModel::dispense('test_jsons');
        $model2->data = [];
        $model2->store();

        $loaded2 = VersaModel::load('test_jsons', $model2->id);
        static::assertIsArray($loaded2->data);
        static::assertEmpty($loaded2->data);

        // Array con elementos mixtos
        $model3 = VersaModel::dispense('test_jsons');
        $model3->data = [1, 'two', 3.0, true, null, ['nested']];
        $model3->store();

        $loaded3 = VersaModel::load('test_jsons', $model3->id);
        static::assertCount(6, $loaded3->data);

        self::$orm->schemaDrop('test_jsons');
    }

    /**
     * Test: TIMESTAMP con zonas horarias y valores extremos.
     */
    public function test_timestamp_edge_cases(): void
    {
        self::$orm->schemaCreate('test_timestamps', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'created', 'type' => 'TIMESTAMP'],
            ['name' => 'updated', 'type' => 'TIMESTAMP'],
        ]);

        // Fecha muy antigua (cerca del límite UNIX epoch)
        $model = VersaModel::dispense('test_timestamps');
        $model->created = '1970-01-01 00:00:01';
        $model->updated = '1970-01-01 00:00:01';
        $model->store();

        $loaded = VersaModel::load('test_timestamps', $model->id);
        // Timestamps are now properly cast to DateTime objects
        static::assertInstanceOf(\DateTime::class, $loaded->created);
        static::assertStringContainsString('1970-01-01', $loaded->created->format('Y-m-d H:i:s'));

        // Fecha futura
        $model2 = VersaModel::dispense('test_timestamps');
        $model2->created = '2099-12-31 23:59:59';
        $model2->store();

        $loaded2 = VersaModel::load('test_timestamps', $model2->id);
        static::assertInstanceOf(\DateTime::class, $loaded2->created);
        static::assertStringContainsString('2099-12-31', $loaded2->created->format('Y-m-d H:i:s'));

        // Fecha actual precisa con microsegundos
        $now = date('Y-m-d H:i:s');
        $model3 = VersaModel::dispense('test_timestamps');
        $model3->created = $now;
        $model3->store();

        $loaded3 = VersaModel::load('test_timestamps', $model3->id);
        static::assertInstanceOf(\DateTime::class, $loaded3->created);
        static::assertStringContainsString(date('Y-m-d'), $loaded3->created->format('Y-m-d H:i:s'));

        self::$orm->schemaDrop('test_timestamps');
    }

    /**
     * Test: NULL values en todos los tipos de datos.
     */
    public function test_null_values_across_types(): void
    {
        self::$orm->schemaCreate('test_nulls', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'int_val', 'type' => 'INTEGER', 'nullable' => true],
            ['name' => 'str_val', 'type' => 'VARCHAR(255)', 'nullable' => true],
            ['name' => 'bool_val', 'type' => 'BOOLEAN', 'nullable' => true],
            ['name' => 'float_val', 'type' => 'DOUBLE PRECISION', 'nullable' => true],
            ['name' => 'json_val', 'type' => 'JSON', 'nullable' => true],
            ['name' => 'date_val', 'type' => 'TIMESTAMP', 'nullable' => true],
        ]);

        // Todo NULL
        $model = VersaModel::dispense('test_nulls');
        $model->int_val = null;
        $model->str_val = null;
        $model->bool_val = null;
        $model->float_val = null;
        $model->json_val = null;
        $model->date_val = null;
        $model->store();

        $loaded = VersaModel::load('test_nulls', $model->id);
        static::assertNull($loaded->int_val);
        static::assertNull($loaded->str_val);
        static::assertNull($loaded->bool_val);
        static::assertNull($loaded->float_val);
        static::assertNull($loaded->json_val);
        static::assertNull($loaded->date_val);

        // Mezcla de NULL y valores
        $model2 = VersaModel::dispense('test_nulls');
        $model2->int_val = 42;
        $model2->str_val = null;
        $model2->bool_val = true;
        $model2->float_val = null;
        $model2->json_val = ['key' => 'value'];
        $model2->date_val = null;
        $model2->store();

        $loaded2 = VersaModel::load('test_nulls', $model2->id);
        static::assertSame(42, $loaded2->int_val);
        static::assertNull($loaded2->str_val);
        static::assertTrue($loaded2->bool_val);
        static::assertNull($loaded2->float_val);
        static::assertIsArray($loaded2->json_val);
        static::assertNull($loaded2->date_val);

        self::$orm->schemaDrop('test_nulls');
    }

    /**
     * Test: Conversión de tipos implícita vs explícita.
     */
    public function test_type_coercion_strict(): void
    {
        self::$orm->schemaCreate('test_coercion', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'int_field', 'type' => 'INTEGER'],
            ['name' => 'str_field', 'type' => 'VARCHAR(100)'],
        ]);

        // String numérico a INTEGER
        $model = VersaModel::dispense('test_coercion');
        $model->int_field = '123';
        $model->str_field = 'test';
        $model->store();

        $loaded = VersaModel::load('test_coercion', $model->id);
        static::assertIsInt($loaded->int_field);
        static::assertSame(123, $loaded->int_field);
        static::assertIsString($loaded->str_field);

        // Integer a STRING
        $model2 = VersaModel::dispense('test_coercion');
        $model2->int_field = 456;
        $model2->str_field = 789;
        $model2->store();

        $loaded2 = VersaModel::load('test_coercion', $model2->id);
        static::assertIsInt($loaded2->int_field);
        static::assertIsString($loaded2->str_field);
        static::assertSame('789', $loaded2->str_field);

        self::$orm->schemaDrop('test_coercion');
    }

    /**
     * Test: Caracteres especiales y escape en strings.
     */
    public function test_special_characters_escaping(): void
    {
        self::$orm->schemaCreate('test_escape', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'content', 'type' => 'TEXT'],
        ]);

        // SQL injection attempt (debe ser escapado)
        $model = VersaModel::dispense('test_escape');
        $model->content = "'; DROP TABLE users; --";
        $model->store();

        $loaded = VersaModel::load('test_escape', $model->id);
        static::assertSame("'; DROP TABLE users; --", $loaded->content);

        // Comillas y caracteres especiales
        $model2 = VersaModel::dispense('test_escape');
        $model2->content = "She said \"Hello\" and he said 'Hi'";
        $model2->store();

        $loaded2 = VersaModel::load('test_escape', $model2->id);
        static::assertStringContainsString('"Hello"', $loaded2->content);
        static::assertStringContainsString("'Hi'", $loaded2->content);

        // Backslashes
        $model3 = VersaModel::dispense('test_escape');
        $model3->content = 'C:\\Users\\Path\\File.txt';
        $model3->store();

        $loaded3 = VersaModel::load('test_escape', $model3->id);
        static::assertStringContainsString('\\', $loaded3->content);

        self::$orm->schemaDrop('test_escape');
    }

    /**
     * Test: Actualización de tipos múltiples en un solo modelo.
     */
    public function test_mixed_type_updates(): void
    {
        self::$orm->schemaCreate('test_mixed', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'int_val', 'type' => 'INTEGER'],
            ['name' => 'str_val', 'type' => 'VARCHAR(100)'],
            ['name' => 'bool_val', 'type' => 'BOOLEAN'],
            ['name' => 'json_val', 'type' => 'JSON'],
        ]);

        // Crear con valores iniciales
        $model = VersaModel::dispense('test_mixed');
        $model->int_val = 100;
        $model->str_val = 'original';
        $model->bool_val = true;
        $model->json_val = ['original' => 'data'];
        $model->store();

        $id = $model->id;

        // Actualizar todos los campos
        $loaded = VersaModel::load('test_mixed', $id);
        $loaded->int_val = 200;
        $loaded->str_val = 'updated';
        $loaded->bool_val = false;
        $loaded->json_val = ['updated' => 'data', 'new' => 'field'];
        $loaded->store();

        // Verificar
        $final = VersaModel::load('test_mixed', $id);
        static::assertSame(200, $final->int_val);
        static::assertSame('updated', $final->str_val);
        static::assertFalse($final->bool_val);
        static::assertArrayHasKey('new', $final->json_val);

        self::$orm->schemaDrop('test_mixed');
    }
}
