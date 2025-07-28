<?php

namespace VersaORM\Tests;

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

class QueryBuilderErrorTest extends TestCase
{
    private $orm;
    private $queryBuilder;
    
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

    public function testInvalidTableName()
    {
        // Test con nombre de tabla inválido
        $builder = new QueryBuilder($this->orm, '');
        $result = $builder->get();
        
        // En tests debería funcionar con mock data
        $this->assertIsArray($result);
    }

    public function testInvalidColumnInSelect()
    {
        // Test con columna inválida en SELECT
        $result = $this->queryBuilder
            ->select(['', null, 123])
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInvalidWhereConditions()
    {
        // Test con condiciones WHERE inválidas
        $result = $this->queryBuilder
            ->where('', '=', 'value')
            ->get();
        
        $this->assertIsArray($result);
        
        // Test con operador inválido
        $result = $this->queryBuilder
            ->where('column', 'INVALID_OPERATOR', 'value')
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInvalidJoinConditions()
    {
        // Test con JOINs inválidos
        $result = $this->queryBuilder
            ->join('', 'users.id', '=', 'table.user_id')
            ->get();
        
        $this->assertIsArray($result);
        
        // Test con condición de JOIN inválida
        $result = $this->queryBuilder
            ->join('posts', '', '=', 'posts.user_id')
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInvalidLimit()
    {
        // Test con límite negativo
        $result = $this->queryBuilder
            ->limit(-1)
            ->get();
        
        $this->assertIsArray($result);
        
        // Test con límite extremadamente grande
        $result = $this->queryBuilder
            ->limit(999999999)
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInvalidOffset()
    {
        // Test con offset negativo
        $result = $this->queryBuilder
            ->offset(-1)
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInvalidOrderBy()
    {
        // Test con ORDER BY inválido
        $result = $this->queryBuilder
            ->orderBy('', 'ASC')
            ->get();
        
        $this->assertIsArray($result);
        
        // Test con dirección inválida
        $result = $this->queryBuilder
            ->orderBy('name', 'INVALID_DIRECTION')
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInvalidGroupBy()
    {
        // Test con GROUP BY inválido
        $result = $this->queryBuilder
            ->groupBy('')
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInvalidHaving()
    {
        // Test con HAVING sin GROUP BY
        $result = $this->queryBuilder
            ->having('COUNT(*)', '>', 5)
            ->get();
        
        $this->assertIsArray($result);
        
        // Test con HAVING inválido
        $result = $this->queryBuilder
            ->groupBy('department')
            ->having('', '>', 5)
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInsertWithInvalidData()
    {
        // Test con datos vacíos
        $result = $this->queryBuilder->insert([]);
        $this->assertInstanceOf(QueryBuilder::class, $result);
        
        // Test con datos inválidos
        $result = $this->queryBuilder->insert([
            'column' => null,
            '' => 'value',
            123 => 'invalid_key'
        ]);
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    public function testUpdateWithInvalidData()
    {
        // Test con datos vacíos para UPDATE
        $result = $this->queryBuilder
            ->where('id', '=', 1)
            ->update([]);
        
        $this->assertInstanceOf(QueryBuilder::class, $result);
        
        // Test con UPDATE sin WHERE
        $result = $this->queryBuilder->update(['name' => 'New Name']);
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    public function testDeleteWithoutWhere()
    {
        // Test con DELETE sin WHERE (peligroso)
        $result = $this->queryBuilder->delete();
        $this->assertInstanceOf(QueryBuilder::class, $result);
    }

    public function testInvalidWhereInValues()
    {
        // Test con valores vacíos en WHERE IN
        $result = $this->queryBuilder
            ->whereIn('id', [])
            ->get();
        
        $this->assertIsArray($result);
        
        // Test con valores inválidos en WHERE IN
        $result = $this->queryBuilder
            ->whereIn('id', [null, '', false])
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testInvalidWhereBetween()
    {
        // Test con valores iguales en WHERE BETWEEN
        $result = $this->queryBuilder
            ->whereBetween('created_at', '2023-01-01', '2023-01-01')
            ->get();
        
        $this->assertIsArray($result);
        
        // Test con rango invertido
        $result = $this->queryBuilder
            ->whereBetween('created_at', '2023-12-31', '2023-01-01')
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testExcessivelyComplexQuery()
    {
        // Test con query extremadamente compleja
        $builder = $this->queryBuilder
            ->select(['id', 'name', 'email', 'created_at', 'updated_at'])
            ->join('profiles', 'users.id', '=', 'profiles.user_id')
            ->join('posts', 'users.id', '=', 'posts.user_id')
            ->join('comments', 'posts.id', '=', 'comments.post_id')
            ->where('users.active', '=', 1)
            ->where('profiles.public', '=', 1)
            ->where('posts.published', '=', 1)
            ->whereIn('users.role_id', [1, 2, 3, 4, 5])
            ->whereBetween('users.created_at', '2020-01-01', '2023-12-31')
            ->groupBy('users.id')
            ->having('COUNT(posts.id)', '>', 10)
            ->orderBy('users.created_at', 'DESC')
            ->orderBy('posts.created_at', 'DESC')
            ->limit(1000)
            ->offset(5000);
        
        $result = $builder->get();
        $this->assertIsArray($result);
    }

    public function testInvalidChainedMethods()
    {
        // Test con métodos encadenados incorrectamente
        $result = $this->queryBuilder
            ->select()
            ->insert(['name' => 'Test']) // INSERT después de SELECT
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testNullParametersInMethods()
    {
        // Test con parámetros null
        $result = $this->queryBuilder
            ->select(null)
            ->where(null, null, null)
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testVeryLongColumnNames()
    {
        // Test con nombres de columna muy largos
        $longColumn = str_repeat('very_long_column_name_', 100);
        $result = $this->queryBuilder
            ->select([$longColumn])
            ->where($longColumn, '=', 'value')
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testSpecialCharactersInColumnNames()
    {
        // Test con caracteres especiales en nombres de columna
        $result = $this->queryBuilder
            ->select(['user-name', 'user@email', 'user$id', 'user#tag'])
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testUnicodeInValues()
    {
        // Test con valores Unicode
        $result = $this->queryBuilder
            ->where('name', '=', '测试用户')
            ->where('emoji', '=', '🚀🔬💻')
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testBinaryDataInValues()
    {
        // Test con datos binarios
        $binaryData = pack('H*', '48656c6c6f20576f726c64');
        $result = $this->queryBuilder
            ->where('binary_field', '=', $binaryData)
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testFloatingPointPrecision()
    {
        // Test con precisión de punto flotante
        $result = $this->queryBuilder
            ->where('price', '=', 999.999999999999)
            ->where('discount', '>', 0.0000000001)
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testLargeArrayValues()
    {
        // Test con arrays muy grandes en WHERE IN
        $largeArray = range(1, 10000);
        $result = $this->queryBuilder
            ->whereIn('id', $largeArray)
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testMethodCallsAfterExecution()
    {
        // Ejecutar query
        $this->queryBuilder->get();
        
        // Intentar usar el builder después de la ejecución
        $result = $this->queryBuilder
            ->where('id', '=', 1)
            ->get();
        
        $this->assertIsArray($result);
    }

    public function testConcurrentBuilderUsage()
    {
        // Test con uso concurrente del mismo builder
        $builder1 = $this->queryBuilder->where('active', '=', 1);
        $builder2 = $this->queryBuilder->where('deleted', '=', 0);
        
        $result1 = $builder1->get();
        $result2 = $builder2->get();
        
        $this->assertIsArray($result1);
        $this->assertIsArray($result2);
    }

    public function testInsertGetIdWithInvalidData()
    {
        // Test insertGetId con datos inválidos
        $id = $this->queryBuilder->insertGetId([
            'name' => null,
            'email' => '',
            'invalid_json' => ['recursive' => []]
        ]);
        
        // En tests retorna un ID simulado
        $this->assertTrue(is_int($id) || is_null($id));
    }

    public function testCountWithComplexConditions()
    {
        // Test count con condiciones complejas
        $count = $this->queryBuilder
            ->join('profiles', 'users.id', '=', 'profiles.user_id')
            ->where('users.active', '=', 1)
            ->whereIn('users.role_id', [1, 2, 3])
            ->count();
        
        $this->assertIsInt($count);
    }

    public function testFirstWithNoResults()
    {
        // Test first cuando no hay resultados
        $result = $this->queryBuilder
            ->where('id', '=', 999999)
            ->first();
        
        $this->assertTrue(is_array($result) || is_null($result));
    }

    public function testAggregateWithInvalidColumns()
    {
        // Test funciones agregadas con columnas inválidas
        $count = $this->queryBuilder->count('');
        $this->assertIsInt($count);
        
        $count = $this->queryBuilder->count('nonexistent_column');
        $this->assertIsInt($count);
    }
}
