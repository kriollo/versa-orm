<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;
use VersaORM\QueryBuilder;
use VersaORM\VersaORMException;

/**
 * Pruebas para funcionalidades SQL avanzadas - Tarea 7.1
 * 
 * Estas pruebas verifican el correcto funcionamiento de:
 * - Window functions (ROW_NUMBER, RANK, LAG, LEAD, etc.)
 * - CTEs (Common Table Expressions)
 * - UNION operations
 * - Advanced aggregations (percentiles, median, etc.)
 * - JSON operations
 * - Full-text search
 * - Database-specific features
 */
class AdvancedSQLTest extends TestCase
{
    private VersaORM $orm;
    private QueryBuilder $queryBuilder;

    protected function setUp(): void
    {
        // Configuración de prueba con SQLite
        $config = [
            'driver' => 'sqlite',
            'host' => 'localhost',  // Requerido por la validación
            'port' => 3306, // Requerido por la validación
            'database' => ':memory:',
            'username' => '',
            'password' => '',
            'options' => [
                'enable_foreign_keys' => true,
            ]
        ];

        $this->orm = new VersaORM($config);
        $this->queryBuilder = new QueryBuilder($this->orm, 'test_table');

        // Crear tabla de prueba
        $this->createTestTables();
    }

    private function createTestTables(): void
    {
        // Tabla principal para pruebas
        $this->orm->exec("
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                department TEXT,
                salary INTEGER,
                hire_date TEXT,
                data TEXT,
                status TEXT DEFAULT 'active'
            )
        ");

        // Tabla para pruebas de JSON
        $this->orm->exec("
            CREATE TABLE json_test (
                id INTEGER PRIMARY KEY,
                profile TEXT,
                settings TEXT,
                metadata TEXT
            )
        ");

        // Tabla para full-text search
        $this->orm->exec("
            CREATE TABLE articles (
                id INTEGER PRIMARY KEY,
                title TEXT,
                content TEXT,
                category TEXT
            )
        ");

        // Insertar datos de prueba
        $this->insertTestData();
    }

    private function insertTestData(): void
    {
        // Datos para test_table
        $employees = [
            ['name' => 'Alice Johnson', 'department' => 'Engineering', 'salary' => 90000, 'hire_date' => '2020-01-15'],
            ['name' => 'Bob Smith', 'department' => 'Engineering', 'salary' => 85000, 'hire_date' => '2019-03-10'],
            ['name' => 'Carol Williams', 'department' => 'Marketing', 'salary' => 70000, 'hire_date' => '2021-06-20'],
            ['name' => 'David Brown', 'department' => 'Engineering', 'salary' => 95000, 'hire_date' => '2018-11-05'],
            ['name' => 'Eve Davis', 'department' => 'Marketing', 'salary' => 75000, 'hire_date' => '2020-08-12'],
        ];

        foreach ($employees as $employee) {
            $this->orm->exec(
                "INSERT INTO test_table (name, department, salary, hire_date) VALUES (?, ?, ?, ?)",
                array_values($employee)
            );
        }

        // Datos JSON
        $jsonData = [
            [
                'id' => 1,
                'profile' => '{"name": "John Doe", "age": 30, "skills": ["PHP", "JavaScript"]}',
                'settings' => '{"theme": "dark", "notifications": true}',
                'metadata' => '{"created": "2023-01-01", "tags": ["developer", "senior"]}'
            ],
            [
                'id' => 2,
                'profile' => '{"name": "Jane Smith", "age": 28, "skills": ["Python", "React"]}',
                'settings' => '{"theme": "light", "notifications": false}',
                'metadata' => '{"created": "2023-02-15", "tags": ["designer", "junior"]}'
            ],
        ];

        foreach ($jsonData as $row) {
            $this->orm->exec(
                "INSERT INTO json_test (id, profile, settings, metadata) VALUES (?, ?, ?, ?)",
                array_values($row)
            );
        }

        // Datos para artículos
        $articles = [
            ['title' => 'Advanced SQL Techniques', 'content' => 'This article covers window functions and CTEs', 'category' => 'database'],
            ['title' => 'PHP Best Practices', 'content' => 'Learn about modern PHP development patterns', 'category' => 'programming'],
            ['title' => 'Database Optimization', 'content' => 'Tips for optimizing database queries and indexes', 'category' => 'database'],
        ];

        foreach ($articles as $article) {
            $this->orm->exec(
                "INSERT INTO articles (title, content, category) VALUES (?, ?, ?)",
                array_values($article)
            );
        }
    }

    public function testWindowFunctionRowNumber(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');
        
        $result = $qb->windowFunction(
            'row_number',
            '*',
            [],
            ['department'], // PARTITION BY department
            [['column' => 'salary', 'direction' => 'DESC']], // ORDER BY salary DESC
            'row_num'
        );

        $this->assertIsArray($result);
        $this->assertNotEmpty($result);
        
        // Verificar que el resultado contiene la función window
        $this->assertArrayHasKey('row_num', $result[0] ?? []);
    }

    public function testWindowFunctionRank(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');
        
        $result = $qb->windowFunction(
            'rank',
            'salary',
            [],
            ['department'],
            [['column' => 'salary', 'direction' => 'DESC']],
            'salary_rank'
        );

        $this->assertIsArray($result);
        $this->assertNotEmpty($result);
    }

    public function testWindowFunctionLag(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');
        
        $result = $qb->windowFunction(
            'lag',
            'salary',
            ['offset' => 1, 'default_value' => 0],
            ['department'],
            [['column' => 'hire_date', 'direction' => 'ASC']],
            'prev_salary'
        );

        $this->assertIsArray($result);
    }

    public function testWindowFunctionInvalidFunction(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Unsupported window function: invalid_function');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->windowFunction('invalid_function', 'salary');
    }

    public function testWithCte(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $ctes = [
            'high_earners' => [
                'query' => 'SELECT * FROM test_table WHERE salary > 80000',
                'bindings' => []
            ]
        ];

        $result = $qb->withCte(
            $ctes,
            'SELECT department, COUNT(*) as count FROM high_earners GROUP BY department',
            []
        );

        $this->assertIsArray($result);
    }

    public function testWithCteRecursive(): void
    {
        // Crear tabla para pruebas recursivas
        $this->orm->exec("
            CREATE TABLE employees (
                id INTEGER PRIMARY KEY,
                name TEXT,
                manager_id INTEGER REFERENCES employees(id)
            )
        ");

        // Insertar datos jerárquicos
        $this->orm->exec("INSERT INTO employees VALUES (1, 'CEO', NULL)");
        $this->orm->exec("INSERT INTO employees VALUES (2, 'VP Engineering', 1)");
        $this->orm->exec("INSERT INTO employees VALUES (3, 'Senior Developer', 2)");

        $qb = new QueryBuilder($this->orm, 'employees');

        $ctes = [
            'employee_hierarchy' => [
                'query' => '
                    SELECT id, name, manager_id, 0 as level FROM employees WHERE manager_id IS NULL
                    UNION ALL
                    SELECT e.id, e.name, e.manager_id, eh.level + 1
                    FROM employees e
                    JOIN employee_hierarchy eh ON e.manager_id = eh.id
                ',
                'bindings' => []
            ]
        ];

        $result = $qb->withCte(
            $ctes,
            'SELECT * FROM employee_hierarchy ORDER BY level, name',
            []
        );

        $this->assertIsArray($result);
    }

    public function testWithCteEmpty(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('At least one CTE must be provided');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->withCte([], 'SELECT * FROM test');
    }

    public function testUnion(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $queries = [
            [
                'query' => 'SELECT name FROM test_table WHERE department = ?',
                'bindings' => ['Engineering']
            ],
            [
                'query' => 'SELECT name FROM test_table WHERE salary > ?',
                'bindings' => [80000]
            ]
        ];

        $result = $qb->union($queries, 'UNION', [], 10);

        $this->assertIsArray($result);
    }

    public function testUnionAll(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $queries = [
            [
                'query' => 'SELECT department FROM test_table WHERE salary > 70000',
                'bindings' => []
            ],
            [
                'query' => 'SELECT department FROM test_table WHERE department = ?',
                'bindings' => ['Marketing']
            ]
        ];

        $result = $qb->union($queries, 'UNION ALL');

        $this->assertIsArray($result);
    }

    public function testUnionInsufficientQueries(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('UNION operation requires at least 2 queries');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->union([['query' => 'SELECT * FROM test_table']]);
    }

    public function testAdvancedAggregationGroupConcat(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->advancedAggregation(
            'group_concat',
            'name',
            ['separator' => '; '],
            ['department'],
            'employee_names'
        );

        $this->assertIsArray($result);
    }

    public function testAdvancedAggregationPercentile(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->advancedAggregation(
            'percentile',
            'salary',
            ['percentile' => 0.5], // Mediana
            [],
            'median_salary'
        );

        $this->assertIsArray($result);
    }

    public function testAdvancedAggregationMedian(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->advancedAggregation(
            'median',
            'salary',
            [],
            ['department'],
            'median_dept_salary'
        );

        $this->assertIsArray($result);
    }

    public function testAdvancedAggregationVariance(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->advancedAggregation(
            'variance',
            'salary',
            [],
            [],
            'salary_variance'
        );

        $this->assertIsArray($result);
    }

    public function testAdvancedAggregationInvalidType(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Unsupported aggregation type: invalid_type');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->advancedAggregation('invalid_type', 'salary');
    }

    public function testAdvancedAggregationPercentileInvalid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Percentile must be between 0 and 1');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->advancedAggregation('percentile', 'salary', ['percentile' => 1.5]);
    }

    public function testJsonOperationExtract(): void
    {
        $qb = new QueryBuilder($this->orm, 'json_test');

        $result = $qb->jsonOperation(
            'extract',
            'profile',
            ['path' => '$.name'],
            'extracted_name'
        );

        $this->assertIsArray($result);
    }

    public function testJsonOperationArrayLength(): void
    {
        $qb = new QueryBuilder($this->orm, 'json_test');

        $result = $qb->jsonOperation(
            'array_length',
            'profile',
            ['path' => '$.skills'],
            'skills_count'
        );

        $this->assertIsArray($result);
    }

    public function testJsonOperationContains(): void
    {
        $qb = new QueryBuilder($this->orm, 'json_test');

        $result = $qb->jsonOperation(
            'contains',
            'profile',
            ['search_value' => 'PHP'],
            'has_php_skill'
        );

        $this->assertIsArray($result);
    }

    public function testJsonOperationSearch(): void
    {
        $qb = new QueryBuilder($this->orm, 'json_test');

        $result = $qb->jsonOperation(
            'search',
            'settings',
            ['path' => '$.theme', 'value' => 'dark'],
            'has_dark_theme'
        );

        $this->assertIsArray($result);
    }

    public function testJsonOperationInvalid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Unsupported JSON operation: invalid_op');

        $qb = new QueryBuilder($this->orm, 'json_test');
        $qb->jsonOperation('invalid_op', 'profile');
    }

    public function testJsonOperationExtractMissingPath(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('JSON path is required for extract operation');

        $qb = new QueryBuilder($this->orm, 'json_test');
        $qb->jsonOperation('extract', 'profile', []);
    }

    public function testFullTextSearch(): void
    {
        $qb = new QueryBuilder($this->orm, 'articles');

        $result = $qb->fullTextSearch(['title', 'content'], 'SQL database');

        $this->assertIsArray($result);
    }

    public function testFullTextSearchEmptyColumns(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('At least one column is required for full text search');

        $qb = new QueryBuilder($this->orm, 'articles');
        $qb->fullTextSearch([], 'search term');
    }

    public function testFullTextSearchEmptyTerm(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Search term cannot be empty');

        $qb = new QueryBuilder($this->orm, 'articles');
        $qb->fullTextSearch(['title'], '');
    }

    public function testGetDriverCapabilities(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->getDriverCapabilities();

        $this->assertIsArray($result);
        // SQLite debería reportar sus capacidades
        $this->assertArrayHasKey('driver', $result);
    }

    public function testOptimizeQuery(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->optimizeQuery('SELECT * FROM test_table WHERE salary > 50000');

        $this->assertIsArray($result);
    }

    public function testOptimizeQueryEmpty(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Query cannot be empty');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->optimizeQuery('');
    }

    public function testGetDriverLimits(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->getDriverLimits();

        $this->assertIsArray($result);
    }

    public function testCombinedAdvancedFeatures(): void
    {
        // Prueba que combina múltiples características avanzadas
        $qb = new QueryBuilder($this->orm, 'test_table');

        // Usar window function con WHERE conditions
        $result = $qb->where('salary', '>', 70000)
                     ->windowFunction(
                         'row_number',
                         '*',
                         [],
                         ['department'],
                         [['column' => 'salary', 'direction' => 'DESC']],
                         'rank_in_dept'
                     );

        $this->assertIsArray($result);
    }

    public function testAdvancedSQLWithInvalidColumn(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid column name');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->windowFunction('row_number', 'invalid--column');
    }

    public function testAdvancedSQLWithUnsafeExpression(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $ctes = [
            'unsafe' => [
                'query' => 'SELECT * FROM test_table; DROP TABLE users; --',
                'bindings' => []
            ]
        ];
        $qb->withCte($ctes, 'SELECT * FROM unsafe');
    }

    protected function tearDown(): void
    {
        // Limpiar después de cada prueba
        unset($this->orm, $this->queryBuilder);
    }
}
