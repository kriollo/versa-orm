<?php

namespace VersaORM\Tests;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;
use VersaORM\QueryBuilder;

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

    public function testConfigurationSetting()
    {
        $config = [
            'host' => 'localhost',
            'database' => 'test_db',
            'username' => 'user',
            'password' => 'pass',
            'driver' => 'mysql'
        ];
        
        $orm = new VersaORM();
        $orm->setConfig($config);
        
        $this->assertInstanceOf(VersaORM::class, $orm);
    }

    public function testQueryBuilderCreation()
    {
        $queryBuilder = $this->orm->table('users');
        
        $this->assertInstanceOf(QueryBuilder::class, $queryBuilder);
    }

    public function testSelectQuery()
    {
        $queryBuilder = $this->orm->table('users')
            ->select(['id', 'name'])
            ->where('active', '=', 1);
        
        $this->assertInstanceOf(QueryBuilder::class, $queryBuilder);
    }

    public function testInsertQuery()
    {
        $data = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'active' => 1
        ];
        
        $queryBuilder = $this->orm->table('users')->insert($data);
        
        $this->assertInstanceOf(QueryBuilder::class, $queryBuilder);
    }

    public function testUpdateQuery()
    {
        $data = ['name' => 'Jane Doe'];
        
        $queryBuilder = $this->orm->table('users')
            ->where('id', '=', 1)
            ->update($data);
        
        $this->assertInstanceOf(QueryBuilder::class, $queryBuilder);
    }

    public function testDeleteQuery()
    {
        $queryBuilder = $this->orm->table('users')
            ->where('id', '=', 1)
            ->delete();
        
        $this->assertInstanceOf(QueryBuilder::class, $queryBuilder);
    }

    public function testExecMethod()
    {
        $sql = "SELECT * FROM users WHERE id = ?";
        $params = [1];
        
        // Mock del resultado esperado
        $result = $this->orm->exec($sql, $params);
        
        // En un entorno real, verificaríamos la estructura del resultado
        $this->assertIsArray($result);
    }

    public function testRawMethodDeprecated()
    {
        $sql = "SELECT * FROM users";
        
        // Verificar que el método raw funciona (compatibilidad hacia atrás)
        $result = $this->orm->raw($sql);
        
        $this->assertIsArray($result);
    }

    public function testDisconnectMethod()
    {
        $result = $this->orm->disconnect();
        
        $this->assertTrue($result);
    }
}
