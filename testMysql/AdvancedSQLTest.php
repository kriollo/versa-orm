<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

/**
 * Pruebas para funcionalidades SQL avanzadas - Tarea 7.1.
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
/**
 * @group mysql
 */
class AdvancedSQLTest extends TestCase
{
    private ?VersaORM $orm = null;

    private ?QueryBuilder $queryBuilder = null;

    protected function setUp(): void
    {
        // Configuración directa (sin bootstrap global que interfiere)
        $config = [
            'driver' => 'mysql',
            'database' => 'versaorm_test',
            'debug' => true,
            'host' => 'localhost',
            'port' => 3306,
            'username' => 'local',
            'password' => 'local',
        ];

        $this->orm = new VersaORM($config);
        $this->queryBuilder = new QueryBuilder($this->orm, 'test_table');

        // Crear tabla de prueba
        $this->createTestTables();
    }

    protected function tearDown(): void
    {
        // Limpiar después de cada prueba
        $this->orm = null;
        $this->queryBuilder = null;
    }

    public function test_window_function_row_number(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->windowFunction(
            'row_number',
            '*',
            [],
            ['department'], // PARTITION BY department
            [['column' => 'salary', 'direction' => 'DESC']], // ORDER BY salary DESC
            'row_num',
        );

        self::assertIsArray($result);
        self::assertNotEmpty($result);

        // Verificar que el resultado contiene la función window
        self::assertArrayHasKey('row_num', $result[0] ?? []);
    }

    public function test_window_function_rank(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->windowFunction(
            'rank',
            'salary',
            [],
            ['department'],
            [['column' => 'salary', 'direction' => 'DESC']],
            'salary_rank',
        );

        self::assertIsArray($result);
        self::assertNotEmpty($result);
    }

    public function test_window_function_lag(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->windowFunction(
            'lag',
            'salary',
            ['offset' => 1, 'default_value' => 0],
            ['department'],
            [['column' => 'hire_date', 'direction' => 'ASC']],
            'prev_salary',
        );

        self::assertIsArray($result);
    }

    public function test_window_function_invalid_function(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Unsupported window function: invalid_function');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->windowFunction('invalid_function', 'salary');
    }

    public function test_with_cte(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $ctes = [
            'high_earners' => [
                'query' => 'SELECT * FROM test_table WHERE salary > 80000',
                'bindings' => [],
            ],
        ];

        $result = $qb->withCte(
            $ctes,
            'SELECT department, COUNT(*) as count FROM high_earners GROUP BY department',
            [],
        );

        self::assertIsArray($result);
    }

    public function test_with_cte_recursive(): void
    {
        // Crear tabla para pruebas recursivas (MySQL syntax)
        $this->orm->exec('DROP TABLE IF EXISTS employees');
        $this->orm->exec('
            CREATE TABLE employees (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255),
                manager_id INT,
                FOREIGN KEY (manager_id) REFERENCES employees(id)
            )
        ');

        // Insertar datos jerárquicos
        $this->orm->exec("INSERT INTO employees VALUES (1, 'CEO', NULL)");
        $this->orm->exec("INSERT INTO employees VALUES (2, 'VP Engineering', 1)");
        $this->orm->exec("INSERT INTO employees VALUES (3, 'Senior Developer', 2)");

        $qb = new QueryBuilder($this->orm, 'employees');

        $ctes = [
            'employee_hierarchy' => [
                'query' => 'SELECT id, name, manager_id, 0 as level FROM employees WHERE manager_id IS NULL',
                'bindings' => [],
            ],
        ];

        $result = $qb->withCte(
            $ctes,
            'SELECT * FROM employee_hierarchy ORDER BY level, name',
            [],
        );

        self::assertIsArray($result);
    }

    public function test_with_cte_empty(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('At least one CTE must be provided');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->withCte([], 'SELECT * FROM test');
    }

    public function test_union(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $queries = [
            [
                'sql' => 'SELECT name FROM test_table WHERE department = ?',
                'bindings' => ['Engineering'],
            ],
            [
                'sql' => 'SELECT name FROM test_table WHERE salary > ?',
                'bindings' => [80000],
            ],
        ];

        $result = $qb->union($queries, false); // false = UNION (no ALL)

        self::assertIsArray($result);
    }

    public function test_union_all(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $queries = [
            [
                'sql' => 'SELECT department FROM test_table WHERE salary > 70000',
                'bindings' => [],
            ],
            [
                'sql' => 'SELECT department FROM test_table WHERE department = ?',
                'bindings' => ['Marketing'],
            ],
        ];

        $result = $qb->union($queries, true); // true = UNION ALL

        self::assertIsArray($result);
    }

    public function test_union_insufficient_queries(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Each UNION query must have sql and bindings keys');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->union([['sql' => 'SELECT * FROM test_table']]);
    }

    public function test_advanced_aggregation_group_concat(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->advancedAggregation(
            'group_concat',
            'name',
            ['separator' => '; '],
            ['department'],
            'employee_names',
        );

        self::assertIsArray($result);
    }

    public function test_advanced_aggregation_percentile(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->advancedAggregation(
            'percentile',
            'salary',
            ['percentile' => 0.5], // Mediana
            [],
            'median_salary',
        );

        self::assertIsArray($result);
    }

    public function test_advanced_aggregation_median(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->advancedAggregation(
            'median',
            'salary',
            [],
            ['department'],
            'median_dept_salary',
        );

        self::assertIsArray($result);
    }

    public function test_advanced_aggregation_variance(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->advancedAggregation(
            'variance',
            'salary',
            [],
            [],
            'salary_variance',
        );

        self::assertIsArray($result);
    }

    public function test_advanced_aggregation_invalid_type(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid aggregation type: invalid_type');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->advancedAggregation('invalid_type', 'salary');
    }

    public function test_advanced_aggregation_percentile_invalid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Percentile must be between 0 and 1');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->advancedAggregation('percentile', 'salary', ['percentile' => 1.5]);
    }

    public function test_json_operation_extract(): void
    {
        $qb = new QueryBuilder($this->orm, 'json_test');

        $result = $qb->jsonOperation(
            'extract',
            'profile',
            '$.name',
        );

        self::assertIsArray($result);
    }

    public function test_json_operation_array_length(): void
    {
        $qb = new QueryBuilder($this->orm, 'json_test');

        $result = $qb->jsonOperation(
            'array_length',
            'profile',
            '$.skills',
        );

        self::assertIsArray($result);
    }

    public function test_json_operation_contains(): void
    {
        $qb = new QueryBuilder($this->orm, 'json_test');

        $result = $qb->jsonOperation(
            'contains',
            'profile',
            '$.skills',
            'PHP',
        );

        self::assertIsArray($result);
    }

    public function test_json_operation_search(): void
    {
        $qb = new QueryBuilder($this->orm, 'json_test');

        $result = $qb->jsonOperation(
            'search',
            'settings',
            '$.theme',
            'dark',
        );

        self::assertIsArray($result);
    }

    public function test_json_operation_invalid(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid JSON operation: invalid_op. Valid operations: extract, contains, search, array_length, type, keys');

        $qb = new QueryBuilder($this->orm, 'json_test');
        $qb->jsonOperation('invalid_op', 'profile');
    }

    public function test_json_operation_extract_missing_path(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('JSON operation extract requires a path');

        $qb = new QueryBuilder($this->orm, 'json_test');
        $qb->jsonOperation('extract', 'profile', '');
    }

    public function test_full_text_search(): void
    {
        $qb = new QueryBuilder($this->orm, 'articles');

        $result = $qb->fullTextSearch(['title', 'content'], 'SQL database');

        self::assertIsArray($result);
    }

    public function test_full_text_search_empty_columns(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('At least one column must be specified for full-text search');

        $qb = new QueryBuilder($this->orm, 'articles');
        $qb->fullTextSearch([], 'search term');
    }

    public function test_full_text_search_empty_term(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Search term cannot be empty');

        $qb = new QueryBuilder($this->orm, 'articles');
        $qb->fullTextSearch(['title'], '');
    }

    public function test_get_driver_capabilities(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->getDriverCapabilities();

        self::assertIsArray($result);
        // SQLite debería reportar sus capacidades
        self::assertArrayHasKey('driver', $result);
    }

    public function test_optimize_query(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->optimizeQuery(['query' => 'SELECT * FROM test_table WHERE salary > 50000']);

        self::assertIsArray($result);
    }

    public function test_optimize_query_empty(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Query cannot be empty');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->optimizeQuery([]);
    }

    public function test_get_driver_limits(): void
    {
        $qb = new QueryBuilder($this->orm, 'test_table');

        $result = $qb->getDriverLimits();

        self::assertIsArray($result);
    }

    public function test_combined_advanced_features(): void
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
                'rank_in_dept',
            );

        self::assertIsArray($result);
    }

    public function test_advanced_sql_with_invalid_column(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid column name');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $qb->windowFunction('row_number', 'invalid--column');
    }

    public function test_advanced_sql_with_unsafe_expression(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Potentially unsafe');

        $qb = new QueryBuilder($this->orm, 'test_table');
        $ctes = [
            'unsafe' => [
                'query' => 'SELECT * FROM test_table; DROP TABLE users; --',
                'bindings' => [],
            ],
        ];
        $qb->withCte($ctes, 'SELECT * FROM unsafe');
    }

    private function createTestTables(): void
    {
        // Limpiar tablas primero
        $this->orm->exec('DROP TABLE IF EXISTS test_table');
        $this->orm->exec('DROP TABLE IF EXISTS json_test');
        $this->orm->exec('DROP TABLE IF EXISTS articles');

        // Tabla principal para pruebas (MySQL syntax)
        $this->orm->exec("
            CREATE TABLE test_table (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                department VARCHAR(100),
                salary INT,
                hire_date DATE,
                data JSON,
                status VARCHAR(50) DEFAULT 'active'
            )
        ");

        // Tabla para pruebas de JSON
        $this->orm->exec('
            CREATE TABLE json_test (
                id INT AUTO_INCREMENT PRIMARY KEY,
                profile JSON,
                settings JSON,
                metadata JSON
            )
        ');

        // Tabla para full-text search
        $this->orm->exec('
            CREATE TABLE articles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255),
                content TEXT,
                category VARCHAR(100),
                FULLTEXT(title, content)
            )
        ');

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
                'INSERT INTO test_table (name, department, salary, hire_date) VALUES (?, ?, ?, ?)',
                array_values($employee),
            );
        }

        // Datos JSON
        $jsonData = [
            [
                'id' => 1,
                'profile' => '{"name": "John Doe", "age": 30, "skills": ["PHP", "JavaScript"]}',
                'settings' => '{"theme": "dark", "notifications": true}',
                'metadata' => '{"created": "2023-01-01", "tags": ["developer", "senior"]}',
            ],
            [
                'id' => 2,
                'profile' => '{"name": "Jane Smith", "age": 28, "skills": ["Python", "React"]}',
                'settings' => '{"theme": "light", "notifications": false}',
                'metadata' => '{"created": "2023-02-15", "tags": ["designer", "junior"]}',
            ],
        ];

        foreach ($jsonData as $row) {
            $this->orm->exec(
                'INSERT INTO json_test (id, profile, settings, metadata) VALUES (?, ?, ?, ?)',
                array_values($row),
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
                'INSERT INTO articles (title, content, category) VALUES (?, ?, ?)',
                array_values($article),
            );
        }
    }
}
