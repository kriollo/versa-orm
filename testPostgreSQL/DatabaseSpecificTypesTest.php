<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use DateTime;
use Exception;
use InvalidArgumentException;
use VersaORM\VersaModel;

/**
 * Tests de tipos específicos por base de datos
 * Prueba el manejo de tipos avanzados en MySQL, PostgreSQL y SQLite.
 */
class DatabaseSpecificTypesTest extends TestCase
{
    private string $databaseType;

    protected function setUp(): void
    {
        // Determinar tipo en base al driver activo del TestCase unificado
        $this->databaseType = self::$orm->getConfig()['driver'] ?? 'mysql';
        VersaModel::setORM(self::$orm);
    }

    protected function tearDown(): void
    {
        // Limpiar después de cada test
        if (self::$orm) {
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
                    self::$orm->schemaDrop($table);
                } catch (Exception $e) {
                    // Ignorar errores de limpieza
                }
            }
        }
    }

    /**
     * @group mysql
     */
    public function test_my_sql_specific_types(): void
    {
        if ($this->databaseType !== 'mysql') {
            static::assertTrue(true); // Excluido por grupo en suite PostgreSQL

            return;
        }

        self::$orm->freeze(false);

        $model = new VersaModel('test_mysql_types', self::$orm);

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

    /**
     * @group postgres
     */
    public function test_postgre_sql_specific_types(): void
    {
        if ($this->databaseType !== 'postgresql') {
            static::assertTrue(true);

            return;
        }
        // Crear tabla con tipos específicos de PostgreSQL
        self::$orm->schemaCreate(
            'test_postgresql_types',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'uuid', 'type' => 'UUID'],
                ['name' => 'data', 'type' => 'JSONB'],
                ['name' => 'ip_address', 'type' => 'INET'],
                ['name' => 'text_array', 'type' => 'TEXT[]'],
                ['name' => 'network', 'type' => 'CIDR'],
                ['name' => 'mac_address', 'type' => 'MACADDR'],
            ],
            ['if_not_exists' => true],
        );
        $model = new VersaModel('test_postgresql_types', self::$orm);

        // Test UUID
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        $model->uuid = $uuid;
        $model->store();
        static::assertSame($uuid, $model->uuid);

        // Test JSONB
        $jsonData = ['key' => 'value', 'nested' => ['array' => [1, 2, 3]]];
        $model->data = $jsonData;
        $model->store();
        static::assertSame($jsonData, $model->data);

        // Test INET
        $ip = '192.168.1.1';
        $model->ip_address = $ip;
        $model->store();
        static::assertSame($ip, $model->ip_address);

        // Test PostgreSQL Arrays
        $textArray = ['item1', 'item2', 'item3'];
        // Para Postgres ARRAY, usar literal {..}
        $model->text_array = '{' . implode(',', $textArray) . '}';
        $model->store();
        static::assertIsString($model->text_array);

        // Test CIDR
        $cidr = '192.168.1.0/24';
        $model->network = $cidr;
        $model->store();
        static::assertSame($cidr, $model->network);

        // Test MACADDR
        $mac = '08:00:2b:01:02:03';
        $model->mac_address = $mac;
        $model->store();
        static::assertSame($mac, $model->mac_address);
    }

    /**
     * @group sqlite
     */
    public function test_sq_lite_specific_types(): void
    {
        if ($this->databaseType !== 'sqlite') {
            static::assertTrue(true);

            return;
        }

        $model = new VersaModel('test_sqlite_types', self::$orm);

        // SQLite maneja JSON como TEXT
        $jsonData = ['key' => 'value', 'number' => 42];
        $model->json_data = $jsonData;
        $model->store();
        static::assertSame($jsonData, $model->json_data);

        // SQLite BLOB
        $binaryData = base64_encode('binary data test');
        $model->blob_data = $binaryData;
        $model->store();
        static::assertSame($binaryData, $model->blob_data);

        // SQLite maneja fechas como strings
        $dateString = '2024-01-15 12:30:45';
        $model->datetime_field = $dateString;
        $model->store();
        static::assertIsString($model->datetime_field);
    }

    public function test_type_casting_consistency(): void
    {
        $model = new VersaModel('test_type_casting', self::$orm);

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
        // Crear tabla para binarios
        self::$orm->schemaCreate(
            'test_binary',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'binary_field', 'type' => 'TEXT'],
            ],
            ['if_not_exists' => true],
        );
        $model = new VersaModel('test_binary', self::$orm);

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
        // Crear tabla para mapeo complejo
        self::$orm->schemaCreate(
            'test_complex_mapping',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'complex_data', 'type' => 'JSONB'],
            ],
            ['if_not_exists' => true],
        );
        $model = new VersaModel('test_complex_mapping', self::$orm);

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

        static::assertIsArray($model->complex_data);
        static::assertSame('dark', $model->complex_data['user_preferences']['theme']);
        static::assertContains('admin', $model->complex_data['permissions']);
    }

    public function test_type_validation_errors(): void
    {
        // Crear un modelo de prueba con tipos definidos
        $testModel = new class('test_validation', self::$orm) extends VersaModel {
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

        $model = new VersaModel('test_performance', self::$orm);
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
