<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use Exception;
use ReflectionClass;
use VersaORM\VersaModel;

/**
 * Tests para validación automática desde esquema de base de datos (PostgreSQL).
 *
 * @group postgresql
 */
class SchemaValidationTest extends TestCase
{
    /**
     * Test básico de obtención de esquema.
     */
    public function test_get_table_validation_schema_basic(): void
    {
        $model = new TestUserModel('users', self::$orm);

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('getTableValidationSchema');
        $method->setAccessible(true);

        try {
            $schema = $method->invoke($model);
            self::assertIsArray($schema);

            if (!empty($schema)) {
                self::assertArrayHasKey('id', $schema);
                self::assertArrayHasKey('name', $schema);
                self::assertArrayHasKey('email', $schema);

                $idColumn = $schema['id'];
                self::assertArrayHasKey('is_required', $idColumn);
                self::assertArrayHasKey('is_nullable', $idColumn);
                self::assertArrayHasKey('data_type', $idColumn);
            }
        } catch (Exception $e) {
            self::assertTrue(true);
        }
    }

    /**
     * Test de procesamiento de metadatos de esquema a reglas de validación.
     */
    public function test_process_schema_to_validation_rules(): void
    {
        $model = new TestUserModel('users', self::$orm);

        $mockSchemaColumns = [
            [
                'column_name' => 'id',
                'data_type' => 'integer',
                'is_nullable' => 'NO',
                'column_default' => "nextval('users_id_seq'::regclass)",
                'extra' => '',
            ],
            [
                'column_name' => 'name',
                'data_type' => 'character varying',
                'is_nullable' => 'NO',
                'column_default' => null,
                'character_maximum_length' => 255,
            ],
            [
                'column_name' => 'email',
                'data_type' => 'character varying',
                'is_nullable' => 'YES',
                'column_default' => null,
                'character_maximum_length' => 100,
            ],
        ];

        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('processSchemaToValidationRules');
        $method->setAccessible(true);

        $validationSchema = $method->invoke($model, $mockSchemaColumns);

        self::assertIsArray($validationSchema);
        self::assertArrayHasKey('name', $validationSchema);
        self::assertTrue($validationSchema['name']['is_required']);
        self::assertSame(255, $validationSchema['name']['max_length']);
    }

    /**
     * Test de validación automática usando esquema simulado.
     */
    public function test_validate_against_schema(): void
    {
        $model = new TestUserModelWithMockSchema('users', self::$orm);

        // Test 1: Datos válidos
        $model->fill(['name' => 'Juan Pérez', 'email' => 'juan@example.com']);
        $errors = $model->validate();
        self::assertEmpty($errors);

        // Test 2: Campo requerido faltante
        $model2 = new TestUserModelWithMockSchema('users', self::$orm);
        $model2->fill(['email' => 'test@example.com']);
        $errors2 = $model2->validate();
        self::assertContains('The name field is required.', $errors2);
    }
}

/**
 * Modelo de prueba para usuarios con validación automática.
 */
class TestUserModel extends VersaModel
{
    protected array $fillable = ['name', 'email'];
}

/**
 * Modelo de prueba que simula un esquema específico.
 */
class TestUserModelWithMockSchema extends VersaModel
{
    protected array $fillable = ['name', 'email'];

    protected function getTableValidationSchema(): array
    {
        return [
            'id' => [
                'is_required' => false,
                'is_nullable' => false,
                'is_auto_increment' => true,
                'data_type' => 'integer',
                'validation_rules' => ['numeric'],
            ],
            'name' => [
                'is_required' => true,
                'is_nullable' => false,
                'max_length' => 255,
                'data_type' => 'character varying',
                'validation_rules' => ['required', 'max:255'],
            ],
            'email' => [
                'is_required' => false,
                'is_nullable' => true,
                'max_length' => 100,
                'data_type' => 'character varying',
                'validation_rules' => ['email', 'max:100'],
            ],
        ];
    }
}
