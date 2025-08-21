<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

/**
 * Test para la validación automática desde esquema obtenido via CLI Rust.
 */
class ValidationSchemaTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Crear tabla de prueba simulando CLI Rust schema (PostgreSQL compatible)
        self::$orm->schemaCreate('test_validation_schema', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
            ['name' => 'email', 'type' => 'VARCHAR(255)', 'nullable' => false],
            ['name' => 'age', 'type' => 'INT'],
            ['name' => 'balance', 'type' => 'DECIMAL(10,2)'],
            ['name' => 'bio', 'type' => 'TEXT'],
            ['name' => 'is_active', 'type' => 'BOOLEAN', 'default' => true],
            ['name' => 'created_at', 'type' => 'TIMESTAMP'],
        ], ['if_not_exists' => true]);
    }

    public function test_schema_validation_with_required_fields(): void
    {
        $model = new class ('test_validation_schema', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email', 'age', 'balance', 'bio', 'is_active'];

            protected function getTableValidationSchema(): array
            {
                return [
                    'name' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'max_length' => 255,
                        'data_type' => 'varchar',
                        'validation_rules' => ['required'],
                    ],
                    'email' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'max_length' => 255,
                        'data_type' => 'varchar',
                        'validation_rules' => ['required', 'email'],
                    ],
                    'age' => [
                        'is_required' => false,
                        'is_nullable' => true,
                        'data_type' => 'int',
                    ],
                    'balance' => [
                        'is_required' => false,
                        'is_nullable' => true,
                        'data_type' => 'decimal',
                        'validation_rules' => ['numeric'],
                    ],
                ];
            }
        };

        // Test: Datos válidos
        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com', 'age' => 30, 'balance' => 1000.50]);
        $errors = $model->validate();
        self::assertEmpty($errors, 'Valid data should not produce validation errors');
    }

    public function test_schema_validation_fails_on_required_fields(): void
    {
        $model = new class ('test_validation_schema', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email', 'age', 'balance'];

            protected function getTableValidationSchema(): array
            {
                return [
                    'name' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'max_length' => 255,
                        'data_type' => 'varchar',
                    ],
                    'email' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'max_length' => 255,
                        'data_type' => 'varchar',
                    ],
                ];
            }
        };

        // Test: Campo requerido vacío
        $model->fill(['name' => '', 'email' => 'john@example.com']);
        $errors = $model->validate();
        self::assertNotEmpty($errors);
        self::assertContains('The name field is required.', $errors);
    }

    public function test_schema_validation_max_length(): void
    {
        $model = new class ('test_validation_schema', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected function getTableValidationSchema(): array
            {
                return [
                    'name' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'max_length' => 10,
                        'data_type' => 'varchar',
                    ],
                ];
            }
        };

        // Test: Exceder longitud máxima
        $model->fill(['name' => 'This is a very long name that exceeds the limit']);
        $errors = $model->validate();
        self::assertNotEmpty($errors);
        self::assertContains('The name may not be greater than 10 characters.', $errors);
    }

    public function test_schema_validation_data_types(): void
    {
        $model = new class ('test_validation_schema', self::$orm) extends VersaModel {
            protected array $fillable = ['age', 'balance'];

            protected function getTableValidationSchema(): array
            {
                return [
                    'age' => [
                        'is_required' => false,
                        'is_nullable' => true,
                        'data_type' => 'int',
                    ],
                    'balance' => [
                        'is_required' => false,
                        'is_nullable' => true,
                        'data_type' => 'decimal',
                    ],
                ];
            }
        };

        // Test: Tipo de datos incorrecto para entero
        $model->fill(['age' => 'not-a-number']);
        $errors = $model->validate();
        self::assertNotEmpty($errors);
        self::assertContains('The age must be an integer.', $errors);

        // Test: Tipo de datos incorrecto para decimal
        $model->fill(['balance' => 'not-a-decimal']);
        $errors = $model->validate();
        self::assertNotEmpty($errors);
        self::assertContains('The balance must be a number.', $errors);
    }

    public function test_schema_validation_with_nullable_fields(): void
    {
        $model = new class ('test_validation_schema', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'age', 'bio'];

            protected function getTableValidationSchema(): array
            {
                return [
                    'name' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'max_length' => 255,
                        'data_type' => 'varchar',
                    ],
                    'age' => [
                        'is_required' => false,
                        'is_nullable' => true,
                        'data_type' => 'int',
                    ],
                    'bio' => [
                        'is_required' => false,
                        'is_nullable' => true,
                        'data_type' => 'text',
                    ],
                ];
            }
        };

        // Test: Campos nullable con valores null
        $model->fill(['name' => 'John Doe', 'age' => null, 'bio' => null]);
        $errors = $model->validate();
        self::assertEmpty($errors, 'Nullable fields with null values should be valid');
    }

    public function test_schema_validation_fallback_to_basic(): void
    {
        $model = new class ('test_validation_schema', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected function getTableValidationSchema(): array
            {
                // Simular que no se puede obtener el esquema
                return [];
            }
        };

        // Cuando no hay esquema disponible, debe usar validación básica
        $model->fill(['name' => 'John Doe', 'email' => 'john@example.com']);
        $errors = $model->validate();
        // La validación básica no debería generar errores para estos datos
        self::assertEmpty($errors);
    }

    public function test_schema_validation_with_custom_rules(): void
    {
        $model = new class ('test_validation_schema', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected array $rules = [
                'name' => ['min:5'], // Regla personalizada adicional
            ];

            protected function getTableValidationSchema(): array
            {
                return [
                    'name' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'max_length' => 255,
                        'data_type' => 'varchar',
                    ],
                    'email' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'max_length' => 255,
                        'data_type' => 'varchar',
                        'validation_rules' => ['email'],
                    ],
                ];
            }
        };

        // Test: Combinación de validación de esquema y reglas personalizadas
        $model->fill(['name' => 'Jo', 'email' => 'invalid-email']);
        $errors = $model->validate();
        self::assertNotEmpty($errors);
        self::assertContains('The name must be at least 5 characters.', $errors);
        self::assertContains('The email must be a valid email address.', $errors);
    }

    public function test_schema_validation_missing_required_fields(): void
    {
        $model = new class ('test_validation_schema', self::$orm) extends VersaModel {
            protected array $fillable = ['name', 'email'];

            protected function getTableValidationSchema(): array
            {
                return [
                    'name' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'is_auto_increment' => false,
                        'max_length' => 255,
                        'data_type' => 'varchar',
                    ],
                    'email' => [
                        'is_required' => true,
                        'is_nullable' => false,
                        'is_auto_increment' => false,
                        'max_length' => 255,
                        'data_type' => 'varchar',
                    ],
                ];
            }
        };

        // Test: Campos requeridos no enviados
        $model->fill(['name' => 'John Doe']); // email falta
        $errors = $model->validate();
        self::assertNotEmpty($errors);
        self::assertContains('The email field is required.', $errors);
    }
}
