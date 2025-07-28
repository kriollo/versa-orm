<?php

namespace VersaORM\Tests;

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

class QueryBuilderTest extends TestCase
{
    private $queryBuilder;
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
        
        $this->queryBuilder = new QueryBuilder($this->orm, 'users');
    }

    public function testSelectWithColumns()
    {
        $builder = $this->queryBuilder->select(['id', 'name', 'email']);
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testSelectAll()
    {
        $builder = $this->queryBuilder->select();
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testWhereClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->where('active', '=', 1);
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testMultipleWhereClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->where('active', '=', 1)
            ->where('status', '=', 'approved');
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testWhereInClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->whereIn('id', [1, 2, 3, 4, 5]);
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testWhereBetweenClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->whereBetween('created_at', '2023-01-01', '2023-12-31');
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testOrderByClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->orderBy('created_at', 'DESC');
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testLimitClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->limit(10);
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testOffsetClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->limit(10)
            ->offset(20);
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testJoinClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->join('profiles', 'users.id', '=', 'profiles.user_id');
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testLeftJoinClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->leftJoin('profiles', 'users.id', '=', 'profiles.user_id');
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testGroupByClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->groupBy('department');
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testHavingClause()
    {
        $builder = $this->queryBuilder
            ->select()
            ->groupBy('department')
            ->having('COUNT(*)', '>', 5);
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testInsertData()
    {
        $data = [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'active' => 1
        ];
        
        $builder = $this->queryBuilder->insert($data);
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testUpdateData()
    {
        $data = [
            'name' => 'Updated User',
            'updated_at' => date('Y-m-d H:i:s')
        ];
        
        $builder = $this->queryBuilder
            ->where('id', '=', 1)
            ->update($data);
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testDeleteRecord()
    {
        $builder = $this->queryBuilder
            ->where('id', '=', 1)
            ->delete();
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testComplexQuery()
    {
        $builder = $this->queryBuilder
            ->select(['users.id', 'users.name', 'profiles.bio'])
            ->join('profiles', 'users.id', '=', 'profiles.user_id')
            ->where('users.active', '=', 1)
            ->where('profiles.public', '=', 1)
            ->orderBy('users.created_at', 'DESC')
            ->limit(20)
            ->offset(0);
        
        $this->assertInstanceOf(QueryBuilder::class, $builder);
    }

    public function testGetMethod()
    {
        $result = $this->queryBuilder->select()->get();
        
        $this->assertIsArray($result);
    }

    public function testFirstMethod()
    {
        $result = $this->queryBuilder->select()->first();
        
        // En un entorno real con datos, esto sería un array o null
        $this->assertTrue(is_array($result) || is_null($result));
    }

    public function testCountMethod()
    {
        $result = $this->queryBuilder->count();
        
        $this->assertIsInt($result);
    }
}
