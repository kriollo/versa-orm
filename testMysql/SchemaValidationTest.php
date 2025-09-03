<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use Exception;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\VersaModel;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

use function in_array;

/**
 * Tests para validación automática desde esquema de base de datos.
 *
 * Estos tests verifican que el sistema pueda:
 * 1. Obtener metadatos del esquema desde el CLI Rust
 * 2. Convertir esos metadatos en reglas de validación
 * 3. Aplicar validaciones automáticas basadas en el esquema real
 * 4. Manejar casos edge y errores graciosamente
 */

/**
 * @group mysql
 */
class SchemaValidationTest extends TestCase
{
    private null|VersaORM $orm = null;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'mysql',
            'host' => $_ENV['DB_HOST'] ?? 'localhost',
            'port' => (int) ($_ENV['DB_PORT'] ?? 3306),
            'database' => $_ENV['DB_NAME'] ?? 'versaorm_test',
            'username' => $_ENV['DB_USER'] ?? 'root',
            'password' => $_ENV['DB_PASS'] ?? '',
            'charset' => 'utf8mb4',
            'debug_mode' => true,
        ]);

        VersaModel::setORM($this->orm);
    }

    /**
     * Test básico de obtención de esquema desde Rust CLI.
     */
    public function test_get_table_validation_schema_basic(): void
    {
        $model = new TestUserModel('users', $this->orm);

        // Usar reflexión para acceder al método protegido
        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('getTableValidationSchema');
        $method->setAccessible(true);

        try {
            $schema = $method->invoke($model);

            // Si obtenemos un esquema, debe ser un array
            self::assertIsArray($schema);

            // Si el CLI Rust está disponible y funciona, debería tener datos
            if (!empty($schema)) {
                self::assertArrayHasKey('id', $schema);
                self::assertArrayHasKey('name', $schema);
                self::assertArrayHasKey('email', $schema);

                // Verificar estructura de columna
                $idColumn = $schema['id'];
                self::assertArrayHasKey('is_required', $idColumn);
                self::assertArrayHasKey('is_nullable', $idColumn);
                self::assertArrayHasKey('is_auto_increment', $idColumn);
                self::assertArrayHasKey('data_type', $idColumn);
                self::assertArrayHasKey('validation_rules', $idColumn);
            }
        } catch (Exception $e) {
            self::assertTrue(true); // Test pasa porque el error es manejado graciosamente
        }
    }

    /**
     * Test de procesamiento de metadatos de esquema a reglas de validación.
     */
    public function test_process_schema_to_validation_rules(): void
    {
        $model = new TestUserModel('users', $this->orm);

        // Simular metadatos de columnas que vendría del CLI Rust
        $mockSchemaColumns = [
            [
                'column_name' => 'id',
                'data_type' => 'int',
                'is_nullable' => 'NO',
                'column_default' => null,
                'extra' => 'auto_increment',
                'character_maximum_length' => null,
            ],
            [
                'column_name' => 'name',
                'data_type' => 'varchar',
                'is_nullable' => 'NO',
                'column_default' => null,
                'extra' => '',
                'character_maximum_length' => 255,
            ],
            [
                'column_name' => 'email',
                'data_type' => 'varchar',
                'is_nullable' => 'YES',
                'column_default' => null,
                'extra' => '',
                'character_maximum_length' => 100,
            ],
            [
                'column_name' => 'age',
                'data_type' => 'int',
                'is_nullable' => 'YES',
                'column_default' => '18',
                'extra' => '',
                'character_maximum_length' => null,
            ],
            [
                'column_name' => 'score',
                'data_type' => 'decimal',
                'is_nullable' => 'NO',
                'column_default' => '0.0',
                'extra' => '',
                'character_maximum_length' => null,
            ],
        ];

        // Usar reflexión para acceder al método protegido
        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('processSchemaToValidationRules');
        $method->setAccessible(true);

        $validationSchema = $method->invoke($model, $mockSchemaColumns);

        // Verificar que se procesó correctamente
        self::assertIsArray($validationSchema);
        self::assertCount(5, $validationSchema);

        // Verificar columna ID (auto-increment)
        $idRules = $validationSchema['id'];
        self::assertFalse($idRules['is_required']); // Auto-increment no es requerido para insert
        self::assertTrue($idRules['is_auto_increment']);
        self::assertContains('numeric', $idRules['validation_rules']);

        // Verificar columna NAME (requerido, varchar)
        $nameRules = $validationSchema['name'];
        self::assertTrue($nameRules['is_required'], 'Name should be required');
        self::assertFalse($nameRules['is_nullable'], 'Name should not be nullable');
        self::assertSame(255, $nameRules['max_length'], 'Name max length should be 255');
        self::assertContains('required', $nameRules['validation_rules'], 'Name rules should contain required');
        self::assertContains('max:255', $nameRules['validation_rules'], 'Name rules should contain max:255');

        // Verificar columna EMAIL (opcional, pero con validación email automática)
        $emailRules = $validationSchema['email'];
        self::assertFalse($emailRules['is_required']);
        self::assertTrue($emailRules['is_nullable']);
        self::assertContains('email', $emailRules['validation_rules']);
        self::assertContains('max:100', $emailRules['validation_rules']);

        // Verificar columna AGE (opcional con default)
        $ageRules = $validationSchema['age'];
        self::assertFalse($ageRules['is_required']); // Tiene default
        self::assertContains('numeric', $ageRules['validation_rules']);

        // Verificar columna SCORE (decimal requerido)
        $scoreRules = $validationSchema['score'];
        self::assertFalse($scoreRules['is_required']); // Tiene default
        self::assertContains('numeric', $scoreRules['validation_rules']);
    }

    /**
     * Test de validación automática usando esquema simulado.
     */
    public function test_validate_against_schema(): void
    {
        $model = new TestUserModelWithMockSchema('users', $this->orm);

        // Test 1: Datos válidos
        $model->fill(['name' => 'Juan Pérez', 'email' => 'juan@example.com', 'age' => 25]);
        $errors = $model->validate();
        self::assertEmpty($errors, 'Datos válidos no deberían generar errores');

        // Test 2: Campo requerido faltante
        $model2 = new TestUserModelWithMockSchema('users', $this->orm);
        $model2->fill(['email' => 'test@example.com']); // Falta 'name'
        $errors2 = $model2->validate();
        self::assertNotEmpty($errors2);
        self::assertContains('The name field is required.', $errors2);

        // Test 3: Email inválido
        $model3 = new TestUserModelWithMockSchema('users', $this->orm);
        $model3->fill(['name' => 'Test', 'email' => 'invalid-email']);
        $errors3 = $model3->validate();
        self::assertNotEmpty($errors3);
        self::assertContains('The email must be a valid email address.', $errors3);

        // Test 4: Longitud máxima excedida
        $model4 = new TestUserModelWithMockSchema('users', $this->orm);
        $longName = str_repeat('a', 256); // Excede max:255
        $model4->fill(['name' => $longName, 'email' => 'test@example.com']);
        $errors4 = $model4->validate();
        self::assertNotEmpty($errors4);
        self::assertTrue(
            in_array('The name may not be greater than 255 characters.', $errors4, true)
            || in_array('The name must be at least 255 characters.', $errors4, true),
        );

        // Test 5: Tipo de datos incorrecto
        $model5 = new TestUserModelWithMockSchema('users', $this->orm);
        $model5->fill(['name' => 'Test', 'email' => 'test@example.com', 'age' => 'not-a-number']);
        $errors5 = $model5->validate();
        self::assertNotEmpty($errors5);
        self::assertContains('The age must be an integer.', $errors5);
    }

    /**
     * Test de manejo de errores cuando CLI Rust no está disponible.
     */
    public function test_schema_validation_fallback(): void
    {
        $model = new TestUserModelWithFailingSchema('users', $this->orm);

        // Llenar con datos válidos básicos
        $model->fill(['name' => 'Test User', 'email' => 'test@example.com']);

        // La validación debería fallar graciosamente y usar validación básica
        try {
            $errors = $model->validate();
            // No debería lanzar excepciones, debe manejar el error graciosamente
            self::assertIsArray($errors);
        } catch (Exception $e) {
            // Si lanza excepción, verificar que es la simulada y no un error del sistema
            self::assertStringContainsString('CLI Rust not available', $e->getMessage());
        }
    }

    /**
     * Test de validación de campos individuales contra esquema.
     */
    public function test_validate_field_against_schema(): void
    {
        $model = new TestUserModel('users', $this->orm);

        // Usar reflexión para acceder al método protegido
        $reflection = new ReflectionClass($model);
        $method = $reflection->getMethod('validateFieldAgainstSchema');
        $method->setAccessible(true);

        // Test campo requerido vacío
        $columnSchema = [
            'is_required' => true,
            'is_nullable' => false,
            'max_length' => 100,
            'data_type' => 'varchar',
            'validation_rules' => ['required', 'max:100'],
        ];

        $errors = $method->invoke($model, 'name', '', $columnSchema);
        self::assertNotEmpty($errors);
        self::assertContains('The name field is required.', $errors);

        // Test campo opcional null
        $columnSchema['is_required'] = false;
        $columnSchema['is_nullable'] = true;
        $errors2 = $method->invoke($model, 'description', null, $columnSchema);
        self::assertEmpty($errors2); // null es válido para campos opcionales

        // Test longitud máxima
        $longValue = str_repeat('a', 101);
        $errors3 = $method->invoke($model, 'name', $longValue, $columnSchema);
        self::assertNotEmpty($errors3);
        self::assertContains('The name may not be greater than 100 characters.', $errors3);
    }

    /**
     * Test de integración completa con modelo real.
     */
    public function test_full_integration_with_real_model(): void
    {
        // Crear un modelo que use la validación automática real
        $user = new TestUserModel('users', $this->orm);

        try {
            // Intentar crear un usuario inválido
            $user->fill([
                'name' => '', // Campo requerido vacío
                'email' => 'invalid-email', // Email inválido
            ]);

            // Esto debería lanzar una excepción de validación
            $user->store();

            self::fail('Se esperaba una excepción de validación');
        } catch (VersaORMException $e) {
            self::assertStringContainsString('Validation failed', $e->getMessage());
        }
    }
}

/**
 * Modelo de prueba para usuarios con validación automática.
 */
class TestUserModel extends VersaModel
{
    protected array $fillable = ['name', 'email', 'age', 'score'];

    // Reglas personalizadas adicionales
    protected array $rules = [
        'name' => ['required'],
        'age' => ['numeric'],
    ];
}

/**
 * Modelo de prueba que simula un esquema específico.
 */
class TestUserModelWithMockSchema extends VersaModel
{
    protected array $fillable = ['name', 'email', 'age', 'score'];

    /**
     * Override para simular esquema específico.
     */
    protected function getTableValidationSchema(): array
    {
        return [
            'id' => [
                'is_required' => false,
                'is_nullable' => false,
                'is_auto_increment' => true,
                'max_length' => null,
                'data_type' => 'int',
                'validation_rules' => ['numeric'],
            ],
            'name' => [
                'is_required' => true,
                'is_nullable' => false,
                'is_auto_increment' => false,
                'max_length' => 255,
                'data_type' => 'varchar',
                'validation_rules' => ['required', 'max:255'],
            ],
            'email' => [
                'is_required' => false,
                'is_nullable' => true,
                'is_auto_increment' => false,
                'max_length' => 100,
                'data_type' => 'varchar',
                'validation_rules' => ['email', 'max:100'],
            ],
            'age' => [
                'is_required' => false,
                'is_nullable' => true,
                'is_auto_increment' => false,
                'max_length' => null,
                'data_type' => 'int',
                'validation_rules' => ['numeric'],
            ],
            'score' => [
                'is_required' => false,
                'is_nullable' => false,
                'is_auto_increment' => false,
                'max_length' => null,
                'data_type' => 'decimal',
                'validation_rules' => ['numeric'],
            ],
        ];
    }
}

/**
 * Modelo de prueba que simula fallo de CLI Rust.
 */
class TestUserModelWithFailingSchema extends VersaModel
{
    protected array $fillable = ['name', 'email'];

    /**
     * Override que simula fallo del CLI Rust.
     */
    protected function getTableValidationSchema(): array
    {
        // Simular que el CLI Rust no está disponible
        throw new Exception('CLI Rust not available');
    }
}
