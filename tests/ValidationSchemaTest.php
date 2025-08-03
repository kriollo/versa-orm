<?php

declare(strict_types=1);

namespace VersaORM\Tests;

use VersaORM\VersaModel;

/**
 * Test para la validación automática desde esquema obtenido via CLI Rust.
 */
class ValidationSchemaTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Crear tabla de prueba simular CLI Rust schema
        self::$orm->exec('CREATE TABLE IF NOT EXISTS test_validation_schema (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            age INT,
            balance DECIMAL(10,2),
            bio TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB');
    }

    public function testSchemaValidationWithRequiredFields(): void
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
        $this->assertEmpty($errors, 'Valid data should not produce validation errors');
    }

    public function testSchemaValidationFailsOnRequiredFields(): void
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
        $this->assertNotEmpty($errors);
        $this->assertContains('The name field is required.', $errors);
    }

    public function testSchemaValidationMaxLength(): void
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
        $this->assertNotEmpty($errors);
        $this->assertContains('The name may not be greater than 10 characters.', $errors);
    }

    public function testSchemaValidationDataTypes(): void
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
        $this->assertNotEmpty($errors);
        $this->assertContains('The age must be an integer.', $errors);

        // Test: Tipo de datos incorrecto para decimal
        $model->fill(['balance' => 'not-a-decimal']);
        $errors = $model->validate();
        $this->assertNotEmpty($errors);
        $this->assertContains('The balance must be a number.', $errors);
    }

    public function testSchemaValidationWithNullableFields(): void
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
        $this->assertEmpty($errors, 'Nullable fields with null values should be valid');
    }

    public function testSchemaValidationFallbackToBasic(): void
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
        $this->assertEmpty($errors);
    }

    public function testSchemaValidationWithCustomRules(): void
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
        $this->assertNotEmpty($errors);
        $this->assertContains('The name must be at least 5 characters.', $errors);
        $this->assertContains('The email must be a valid email address.', $errors);
    }

    public function testSchemaValidationMissingRequiredFields(): void
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
        $this->assertNotEmpty($errors);
        $this->assertContains('The email field is required.', $errors);
    }
}
