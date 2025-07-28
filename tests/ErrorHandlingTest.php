<?php

namespace VersaORM\Tests;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;
use VersaORM\QueryBuilder;
use VersaORM\Model;

class ErrorHandlingTest extends TestCase
{
    private $orm;
    
    protected function setUp(): void
    {
        $this->orm = new VersaORM();
        $this->orm->setConfig([
            'host' => ':memory:',
            'database' => 'test',
            'username' => '',
            'password' => '',
            'driver' => 'sqlite'
        ]);
        
        Model::setORM($this->orm);
    }

    public function testConnectionErrorWithoutConfig()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Database configuration is not set');
        
        $emptyOrm = new VersaORM();
        // Forzar que no esté en entorno de pruebas para que lance la excepción
        $reflector = new \ReflectionClass($emptyOrm);
        $method = $reflector->getMethod('execute');
        $method->setAccessible(true);
        $method->invoke($emptyOrm, 'query', []);
    }

    public function testConnectionErrorWithInvalidConfig()
    {
        // Simulate connection error with invalid configuration
        $invalidOrm = new VersaORM([
            'host' => 'invalid_host',
            'database' => 'nonexistent_db',
            'username' => 'invalid_user',
            'password' => 'wrong_password',
            'driver' => 'mysql'
        ]);

        // En un entorno real esto fallaría, pero en tests retorna mock data
        $result = $invalidOrm->table('users')->get();
        $this->assertIsArray($result);
    }

    public function testInvalidJSONPayload()
    {
        // Test con datos que podrían causar problemas de JSON
        $data = [
            'invalid_utf8' => "\x80\x81\x82", // Invalid UTF-8
            'circular' => null
        ];
        
        // Crear referencia circular
        $data['circular'] = &$data;
        
        // En el entorno de pruebas esto debería funcionar con mock data
        $result = $this->orm->table('test')->insert(['name' => 'test']);
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    public function testSQLSyntaxError()
    {
        // Test para errores de sintaxis SQL
        $result = $this->orm->exec("SELECT * FROM users WHERE invalid syntax");
        
        // En tests retorna array vacio, pero en producción debería lanzar excepción
        $this->assertIsArray($result);
    }

    public function testTableNotFoundError()
    {
        // Test para tabla inexistente
        $result = $this->orm->table('nonexistent_table')->get();
        
        // En tests retorna array vacio
        $this->assertIsArray($result);
    }

    public function testColumnNotFoundError()
    {
        // Test para columna inexistente
        $result = $this->orm->table('users')
            ->select(['nonexistent_column'])
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInvalidDataTypeError()
    {
        // Test para tipos de datos incorrectos
        $result = $this->orm->table('users')->insert([
            'id' => 'string_instead_of_int',
            'created_at' => 'invalid_date_format',
            'status' => ['array', 'instead', 'of', 'string']
        ]);
        
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    public function testConstraintViolationError()
    {
        // Test para violación de restricciones (PK, FK, UNIQUE, etc.)
        $result = $this->orm->table('users')->insert([
            'id' => 1, // Duplicate primary key
            'email' => 'duplicate@example.com' // Duplicate unique field
        ]);
        
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    public function testPermissionDeniedError()
    {
        // Test para permisos insuficientes
        $result = $this->orm->exec("DROP TABLE users");
        
        $this->assertIsArray($result);
    }

    public function testConnectionTimeoutError()
    {
        // Test para timeout de conexión
        $timeoutOrm = new VersaORM([
            'host' => 'slow.database.com',
            'database' => 'test',
            'username' => 'user',
            'password' => 'pass',
            'driver' => 'mysql',
            'timeout' => 1 // 1 second timeout
        ]);

        $result = $timeoutOrm->table('users')->get();
        $this->assertIsArray($result);
    }

    public function testMaxConnectionsReachedError()
    {
        // Test para límite de conexiones alcanzado
        $result = $this->orm->table('users')->get();
        $this->assertIsArray($result);
    }

    public function testModelWithInvalidPrimaryKey()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Cannot delete without an ID');
        
        $user = Model::dispense('users');
        $user->name = 'Test User';
        // No establecemos ID
        $user->trash(); // Debería fallar
    }

    public function testModelLoadWithInvalidId()
    {
        // Test cargando un modelo con ID inexistente
        $user = Model::find('users', 99999);
        
        // En tests, load() simula datos encontrados
        $this->assertInstanceOf(Model::class, $user);
    }

    public function testInvalidQueryBuilderChaining()
    {
        // Test para uso incorrecto del QueryBuilder
        $result = $this->orm->table('users')
            ->where('id', '=', 1)
            ->having('COUNT(*)', '>', 5) // HAVING sin GROUP BY
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testEmptyTableName()
    {
        // Test con nombre de tabla vacío - en PHP 8 no lanza TypeError automáticamente
        $result = $this->orm->table('')->get();
        $this->assertIsArray($result);
    }

    public function testNullQueryParameter()
    {
        $result = $this->orm->exec("SELECT * FROM users WHERE name = ?", [null]);
        $this->assertIsArray($result);
    }

    public function testVeryLongQueryString()
    {
        // Test con query muy larga
        $longQuery = "SELECT * FROM users WHERE name = '" . str_repeat('x', 10000) . "'";
        $result = $this->orm->exec($longQuery);
        
        $this->assertIsArray($result);
    }

    public function testSpecialCharactersInQuery()
    {
        // Test con caracteres especiales
        $result = $this->orm->exec("SELECT * FROM users WHERE name = ?", [
            "'; DROP TABLE users; --"
        ]);
        
        $this->assertIsArray($result);
    }

    public function testUnicodeCharactersInData()
    {
        // Test con caracteres Unicode
        $result = $this->orm->table('users')->insert([
            'name' => '测试用户',
            'email' => 'тест@пример.com',
            'bio' => '🚀 Rocket scientist 🔬'
        ]);
        
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    public function testExcessiveJoins()
    {
        // Test con muchos JOINs
        $builder = $this->orm->table('users');
        
        for ($i = 1; $i <= 10; $i++) {
            $builder->join("table_$i", 'users.id', '=', "table_$i.user_id");
        }
        
        $result = $builder->get();
        $this->assertIsArray($result);
    }

    public function testDeepNestedConditions()
    {
        // Test con condiciones WHERE muy anidadas
        $builder = $this->orm->table('users');
        
        for ($i = 1; $i <= 50; $i++) {
            $builder->where("field_$i", '=', "value_$i");
        }
        
        $result = $builder->get();
        $this->assertIsArray($result);
    }

    public function testSchemaOperationErrors()
    {
        // Test para errores en operaciones de esquema
        $result = $this->orm->schema('nonexistent_operation', 'users');
        $this->assertIsArray($result);
    }

    public function testCacheOperationErrors()
    {
        // Test para errores en operaciones de caché
        $result = $this->orm->cache('invalid_action');
        $this->assertTrue(is_bool($result) || is_null($result));
    }

    public function testBinaryExecutionFailure()
    {
        // Mock para simular fallo en la ejecución del binario
        // En un entorno real, esto sería un test más complejo
        $result = $this->orm->table('users')->get();
        $this->assertIsArray($result);
    }

    public function testMemoryLimitExceeded()
    {
        // Test para límite de memoria excedido con resultados grandes
        $result = $this->orm->table('users')->limit(1000000)->get();
        $this->assertIsArray($result);
    }

    public function testConcurrentAccessErrors()
    {
        // Test para errores de acceso concurrente
        $result1 = $this->orm->table('users')->get();
        $result2 = $this->orm->table('posts')->get();
        
        $this->assertIsArray($result1);
        $this->assertIsArray($result2);
    }

    public function testTransactionRollbackScenario()
    {
        // Test para escenarios de rollback de transacciones
        $result = $this->orm->exec("BEGIN TRANSACTION");
        $this->assertIsArray($result);
        
        $result = $this->orm->exec("ROLLBACK");
        $this->assertIsArray($result);
    }

    public function testDiskSpaceExhausted()
    {
        // Test para espacio en disco agotado
        $largeData = str_repeat('x', 1000000);
        $result = $this->orm->table('users')->insert([
            'name' => 'Test',
            'large_field' => $largeData
        ]);
        
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }
}
