<?php

namespace VersaORM\Tests;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;
use VersaORM\QueryBuilder;
use Exception;

class VersaORMTest extends TestCase
{
    private $orm;
    
    protected function setUp(): void
    {
        // Configuración de prueba con SQLite en memoria
        $this->orm = new VersaORM();
        $this->orm->setConfig([
            'host' => ':memory:',
            'database' => 'test',
            'username' => '',
            'password' => '',
            'driver' => 'sqlite'
        ]);
    }

    public function testSelectNonExistentTable(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("VersaORM Error [TABLE_NOT_FOUND]");

        $query = new QueryBuilder($this->orm, 'tabla_que_no_existe');
        $query->get();
    }

    public function testInvalidSQL(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("VersaORM Error [SYNTAX_ERROR]");

        $this->orm->exec('SELECT * FROM WHERE');
    }

    public function testValidConnection(): void
    {
        $result = $this->orm->exec('SELECT 1 as test');
        $this->assertSame([['test' => 1]], $result);
    }

    public function testExistingTable(): void
    {
        $query = new QueryBuilder($this->orm, 'users');
        $result = $query->get();
        $this->assertIsArray($result);
    }

    public function testSuggestionsInErrorMessage(): void
    {
        try {
            $query = new QueryBuilder($this->orm, 'tabla_que_no_existe');
            $query->get();
            $this->fail('Expected exception was not thrown');
        } catch (Exception $e) {
            $this->assertStringContainsString('Check if the table name is spelled correctly', $e->getMessage());
            $this->assertStringContainsString('Verify the table exists in the database', $e->getMessage());
        }
    }

    public function testInvalidSQLSyntaxWithWhere(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("VersaORM Error [SYNTAX_ERROR]");
        
        $this->orm->exec('SELECT * FROM users WHERE');
    }

    public function testConnectionError(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("VersaORM Error [CONNECTION_ERROR]");
        
        $this->orm->exec('SELECT connection_error FROM test');
    }

    public function testValidQueryReturnsData(): void
    {
        $result = $this->orm->exec('SHOW TABLES');
        $this->assertIsArray($result);
        $this->assertCount(3, $result);
        $this->assertEquals('users', $result[0]['Tables_in_test']);
    }

    public function testQueryBuilderValidTable(): void
    {
        $query = new QueryBuilder($this->orm, 'users');
        $result = $query->get();
        
        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertEquals('Test User', $result[0]['name']);
    }

    public function testQueryBuilderLimit(): void
    {
        $query = new QueryBuilder($this->orm, 'users');
        $result = $query->limit(1)->get();
        
        $this->assertIsArray($result);
    }

    public function testQueryBuilderWhere(): void
    {
        $query = new QueryBuilder($this->orm, 'users');
        $result = $query->where('id', '=', 1)->get();
        
        $this->assertIsArray($result);
    }

    public function testQueryBuilderFirst(): void
    {
        $query = new QueryBuilder($this->orm, 'users');
        $result = $query->first();
        
        $this->assertNull($result);
    }

    public function testQueryBuilderCount(): void
    {
        $query = new QueryBuilder($this->orm, 'users');
        $result = $query->count();
        
        $this->assertIsInt($result);
        $this->assertEquals(0, $result);
    }

    public function testErrorMessageContainsContext(): void
    {
        try {
            $this->orm->exec('SELECT * FROM tabla_que_no_existe');
            $this->fail('Expected exception was not thrown');
        } catch (Exception $e) {
            $this->assertStringContainsString('Context: Action=raw', $e->getMessage());
            $this->assertStringContainsString('Query=SELECT * FROM tabla_que_no_existe', $e->getMessage());
        }
    }

    public function testErrorSuggestions(): void
    {
        // Test table not found error
        try {
            $query = new QueryBuilder($this->orm, 'nonexistent_table');
            $query->get();
            $this->fail('Expected exception was not thrown');
        } catch (Exception $e) {
            $this->assertStringContainsString('Suggestions:', $e->getMessage());
            $this->assertStringContainsString('Check if the table name is spelled correctly', $e->getMessage());
        }

        // Test syntax error
        try {
            $this->orm->exec('INVALID SQL SYNTAX WHERE;');
            $this->fail('Expected exception was not thrown');
        } catch (Exception $e) {
            $this->assertStringContainsString('Check SQL syntax for typos', $e->getMessage());
        }
    }

    public function testDisconnect(): void
    {
        $result = $this->orm->disconnect();
        $this->assertTrue($result);
        
        $this->assertEmpty($this->orm->getConfig());
    }

    public function testVersion(): void
    {
        $version = $this->orm->version();
        $this->assertEquals('1.0.0', $version);
    }

    public function testConfigurationMethods(): void
    {
        $newConfig = [
            'driver' => 'postgresql',
            'host' => 'localhost',
            'port' => 5432,
            'database' => 'test',
            'username' => 'test',
            'password' => 'test'
        ];
        
        $this->orm->setConfig($newConfig);
        $this->assertEquals($newConfig, $this->orm->getConfig());
    }
}
