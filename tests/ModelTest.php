<?php

namespace VersaORM\Tests;

use PHPUnit\Framework\TestCase;
use VersaORM\Model;
use VersaORM\VersaORM;

class ModelTest extends TestCase
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

    public function testDispenseCreatesEmptyModel()
    {
        $user = Model::dispense('users');
        
        $this->assertInstanceOf(Model::class, $user);
        $this->assertEquals('users', $user->getTable());
        $this->assertEmpty($user->getData());
    }

    public function testModelDataManipulation()
    {
        $user = Model::dispense('users');
        
        // Asignar propiedades
        $user->name = 'John Doe';
        $user->email = 'john@example.com';
        $user->active = 1;
        
        $this->assertEquals('John Doe', $user->name);
        $this->assertEquals('john@example.com', $user->email);
        $this->assertEquals(1, $user->active);
    }

    public function testModelDataArray()
    {
        $user = Model::dispense('users');
        $user->name = 'Jane Doe';
        $user->email = 'jane@example.com';
        
        $data = $user->getData();
        
        $this->assertIsArray($data);
        $this->assertEquals('Jane Doe', $data['name']);
        $this->assertEquals('jane@example.com', $data['email']);
    }

    public function testModelLoadMethod()
    {
        $user = Model::load('users', 1);
        
        $this->assertInstanceOf(Model::class, $user);
        $this->assertEquals('users', $user->getTable());
    }

    public function testModelStoreMethod()
    {
        $user = Model::dispense('users');
        $user->name = 'Test User';
        $user->email = 'test@example.com';
        
        $result = $user->store();
        
        // En un entorno real, verificaríamos que el ID fue asignado
        $this->assertIsArray($result);
    }

    public function testModelUpdateExisting()
    {
        $user = Model::dispense('users');
        $user->id = 1;
        $user->name = 'Updated User';
        $user->email = 'updated@example.com';
        
        $result = $user->store();
        
        $this->assertIsArray($result);
    }

    public function testModelTrashMethod()
    {
        $user = Model::dispense('users');
        $user->id = 1;
        
        $result = $user->trash();
        
        $this->assertIsArray($result);
    }

    public function testModelIsset()
    {
        $user = Model::dispense('users');
        $user->name = 'Test User';
        
        $this->assertTrue(isset($user->name));
        $this->assertFalse(isset($user->nonexistent));
    }

    public function testModelUnset()
    {
        $user = Model::dispense('users');
        $user->name = 'Test User';
        $user->email = 'test@example.com';
        
        unset($user->email);
        
        $this->assertTrue(isset($user->name));
        $this->assertFalse(isset($user->email));
    }

    public function testModelWithCustomPrimaryKey()
    {
        $product = Model::dispense('products');
        $product->setPrimaryKey('product_id');
        
        $this->assertEquals('product_id', $product->getPrimaryKey());
    }

    public function testModelFindAll()
    {
        $users = Model::findAll('users');
        
        $this->assertIsArray($users);
    }

    public function testModelFindFirst()
    {
        $user = Model::findFirst('users');
        
        $this->assertTrue($user instanceof Model || $user === null);
    }

    public function testModelWhere()
    {
        $users = Model::where('users', 'active', '=', 1);
        
        $this->assertIsArray($users);
    }

    public function testModelCount()
    {
        $count = Model::count('users');
        
        $this->assertIsInt($count);
    }

    public function testModelChaining()
    {
        $user = Model::dispense('users');
        
        $result = $user
            ->setData(['name' => 'Chain User', 'email' => 'chain@example.com'])
            ->store();
        
        $this->assertIsArray($result);
    }

    public function testModelToArray()
    {
        $user = Model::dispense('users');
        $user->name = 'Array User';
        $user->email = 'array@example.com';
        
        $array = $user->toArray();
        
        $this->assertIsArray($array);
        $this->assertEquals('Array User', $array['name']);
        $this->assertEquals('array@example.com', $array['email']);
    }

    public function testModelFromArray()
    {
        $data = [
            'name' => 'From Array User',
            'email' => 'fromarray@example.com',
            'active' => 1
        ];
        
        $user = Model::dispense('users');
        $user->fromArray($data);
        
        $this->assertEquals('From Array User', $user->name);
        $this->assertEquals('fromarray@example.com', $user->email);
        $this->assertEquals(1, $user->active);
    }
}
