<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use DateTime;
use Exception;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Tests de tipos específicos por base de datos
 * Prueba el manejo de tipos avanzados en MySQL, PostgreSQL y SQLite.
 */
/**
 * @group mysql
 */
class DatabaseSpecificTypesTest extends TestCase
{
    private ?VersaORM $orm = null;

    private string $databaseType;

    protected function setUp(): void
    {
        // Configuración dinámica según la base de datos de prueba
        $this->databaseType = getenv('DB_TYPE') ?: 'mysql';

        $config = $this->getConfigForDatabase($this->databaseType);
        $this->orm = new VersaORM($config);
        VersaModel::setORM($this->orm);
    }

    protected function tearDown(): void
    {
        // Limpiar después de cada test
        if ($this->orm) {
            // Limpiar tablas de test si existen
            $testTables = [
                'test_mysql_types',
                'test_postgresql_types',
                'test_sqlite_types',
                'test_type_casting',
                'test_binary',
                'test_complex_mapping',
                'test_validation',
                'test_performance',
            ];

            foreach ($testTables as $table) {
                try {
                    $this->orm->exec("DROP TABLE IF EXISTS {$table}");
                } catch (Exception $e) {
                    // Ignorar errores de limpieza
                }
            }
        }
    }

    public function test_my_sql_specific_types(): void
    {
        if ($this->databaseType !== 'mysql') {
            static::markTestSkipped('Este test requiere MySQL');
        }

        $this->orm->freeze(false);

        $model = new VersaModel('test_mysql_types', $this->orm);

        // Test ENUM
        $model->status = 'active';
        $model->store();
        static::assertSame('active', $model->status);

        // Test SET
        $model->tags = ['tag1', 'tag2', 'tag3'];
        $model->store();
        static::assertIsArray($model->tags);
        static::assertContains('tag1', $model->tags);

        // Test JSON (MySQL 5.7+)
        $jsonData = ['key' => 'value', 'number' => 42];
        $model->metadata = $jsonData;
        $model->store();
        static::assertSame($jsonData, $model->metadata);

        // Test DECIMAL con precisión
        $model->price = 123.456789;
        $model->store();
        static::assertIsFloat($model->price);

        // Test TIMESTAMP vs DATETIME
        $now = new DateTime();
        $model->created_at = $now;
        $model->store();
        static::assertInstanceOf(DateTime::class, $model->created_at);
    }

    public function test_type_casting_consistency(): void
    {
        $model = new VersaModel('test_type_casting', $this->orm);

        // Test casting de string a JSON
        $model->metadata = '{"key": "value"}';
        $casted = $model->castToPhpType('metadata', $model->metadata);
        static::assertIsArray($casted);
        static::assertSame(['key' => 'value'], $casted);

        // Test casting de array a JSON string para DB
        $array = ['key' => 'value', 'number' => 42];
        $casted = $model->castToDatabaseType('metadata', $array);
        static::assertIsString($casted);
        static::assertSame('{"key":"value","number":42}', $casted);

        // Test UUID validation
        $validUuid = '550e8400-e29b-41d4-a716-446655440000';
        static::assertTrue($this->isValidUuid($validUuid));

        $invalidUuid = 'not-a-uuid';
        static::assertFalse($this->isValidUuid($invalidUuid));
    }

    public function test_binary_data_handling(): void
    {
        $model = new VersaModel('test_binary', $this->orm);

        // Test Base64 encoding/decoding
        $originalData = 'This is binary data with special chars: áéíóú ñ ¿¡';
        $base64Data = base64_encode($originalData);

        $model->binary_field = $base64Data;
        $model->store();

        $decoded = base64_decode($model->binary_field, true);
        static::assertSame($originalData, $decoded);
    }

    public function test_complex_type_mapping(): void
    {
        $model = new VersaModel('test_complex_mapping', $this->orm);

        // Test mapeo de tipo complejo con configuración personalizada
        $complexData = [
            'user_preferences' => [
                'theme' => 'dark',
                'language' => 'es',
                'notifications' => true,
            ],
            'permissions' => ['read', 'write', 'admin'],
            'metadata' => [
                'created_by' => 'system',
                'version' => '1.0.0',
            ],
        ];

        $model->complex_data = $complexData;
        $model->store();

        // MySQL stores JSON as string, so we need to decode it
        $storedData = is_string($model->complex_data) ? json_decode($model->complex_data, true) : $model->complex_data;
        static::assertIsArray($storedData);
        static::assertSame('dark', $storedData['user_preferences']['theme']);
        static::assertContains('admin', $storedData['permissions']);
    }

    public function test_type_validation_errors(): void
    {
        // Crear un modelo de prueba con tipos definidos
        $testModel = new class('test_validation', $this->orm) extends VersaModel {
            public static function getPropertyTypes(): array
            {
                return [
                    'uuid_field' => ['type' => 'uuid'],
                    'email_field' => ['type' => 'email'],
                ];
            }
        };

        // Test UUID inválido
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid UUID format');

        $testModel->castToPhpType('uuid_field', 'invalid-uuid');
    }

    public function test_performance_with_large_datasets(): void
    {
        $startTime = microtime(true);

        // Test con dataset grande
        $largeArray = array_fill(0, 1000, [
            'id' => rand(1, 1000000),
            'name' => 'Test Item ' . rand(1, 1000),
            'data' => ['nested' => array_fill(0, 100, 'value')],
        ]);

        $model = new VersaModel('test_performance', $this->orm);
        $model->large_dataset = $largeArray;

        // El casting debe ser rápido incluso con datos grandes
        $jsonString = $model->castToDatabaseType('large_dataset', $largeArray);
        $backToArray = $model->castToPhpType('large_dataset', $jsonString);

        $endTime = microtime(true);
        $executionTime = $endTime - $startTime;

        static::assertLessThan(1.0, $executionTime, 'El casting debe ser rápido (<1s)');
        static::assertSame($largeArray, $backToArray);
    }

    private function getConfigForDatabase(string $type): array
    {
        $configs = [
            'mysql' => [
                'engine' => 'pdo',
                'database_type' => 'mysql',
                'host' => getenv('DB_HOST') ?: 'localhost',
                'port' => (int) (getenv('DB_PORT') ?: 3306),
                'database' => getenv('DB_NAME') ?: 'versaorm_test',
                'username' => getenv('DB_USER') ?: 'local',
                'password' => getenv('DB_PASS') ?: 'local',
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
            ],
            'postgresql' => [
                'database_type' => 'postgresql',
                'host' => getenv('DB_HOST') ?: 'localhost',
                'port' => (int) (getenv('DB_PORT') ?: 5432),
                'database' => getenv('DB_NAME') ?: 'test_versaorm',
                'username' => getenv('DB_USER') ?: 'postgres',
                'password' => getenv('DB_PASS') ?: '',
                'charset' => 'utf8',
            ],
            'sqlite' => [
                'database_type' => 'sqlite',
                'database' => ':memory:',
            ],
        ];

        return $configs[$type];
    }

    private function isValidUuid(string $uuid): bool
    {
        $pattern = '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

        return preg_match($pattern, $uuid) === 1;
    }
}
