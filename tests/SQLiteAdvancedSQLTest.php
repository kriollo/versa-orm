<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;
use VersaORM\QueryBuilder;
use VersaORM\VersaORMException;

/**
 * Tests específicos para funcionalidades SQL avanzadas de SQLite
 *
 * Estas pruebas verifican:
 * - Window functions en SQLite 3.25+
 * - JSON operations con json_extract
 * - CTEs simples y recursivos
 * - Full-text search con FTS5
 */
class SQLiteAdvancedSQLTest extends TestCase
{
    private VersaORM $orm;
    private QueryBuilder $queryBuilder;

    protected function setUp(): void
    {
        // Configuración específica para SQLite
        $config = [
            'driver' => 'sqlite',
            'host' => 'localhost',
            'port' => 3306,
            'database' => ':memory:',
            'username' => '',
            'password' => '',
            'options' => [
                'enable_foreign_keys' => true,
                'journal_mode' => 'WAL',
            ]
        ];

        $this->orm = new VersaORM($config);
        $this->queryBuilder = new QueryBuilder($this->orm, 'employees');

        $this->createSQLiteTestTables();
    }

    private function createSQLiteTestTables(): void
    {
        // Tabla principal para SQLite
        $this->orm->exec("
            CREATE TABLE employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                department TEXT,
                salary REAL,
                hire_date TEXT,
                profile TEXT,
                bio TEXT
            )
        ");

        // Tabla FTS5 para full-text search
        $this->orm->exec("
            CREATE VIRTUAL TABLE IF NOT EXISTS employees_fts USING fts5(
                name, department, bio,
                content='employees',
                content_rowid='id'
            )
        ");

        // Insertar datos de prueba
        $employees = [
            [
                'name' => 'Alice Johnson',
                'department' => 'Engineering',
                'salary' => 90000.00,
                'hire_date' => '2020-01-15',
                'profile' => '{"skills": ["SQLite", "Python"], "level": "senior"}',
                'bio' => 'Senior SQLite database engineer with optimization expertise'
            ],
            [
                'name' => 'Bob Smith',
                'department' => 'Engineering',
                'salary' => 85000.00,
                'hire_date' => '2019-03-10',
                'profile' => '{"skills": ["C", "SQLite"], "level": "mid"}',
                'bio' => 'Systems programmer specializing in SQLite extensions'
            ],
            [
                'name' => 'Carol Williams',
                'department' => 'Analytics',
                'salary' => 75000.00,
                'hire_date' => '2021-06-20',
                'profile' => '{"skills": ["SQL", "R"], "level": "senior"}',
                'bio' => 'Data analyst using SQLite for embedded analytics'
            ]
        ];

        foreach ($employees as $employee) {
            $this->orm->exec(
                "INSERT INTO employees (name, department, salary, hire_date, profile, bio) VALUES (?, ?, ?, ?, ?, ?)",
                array_values($employee)
            );

            // Poblar tabla FTS
            $this->orm->exec(
                "INSERT INTO employees_fts (rowid, name, department, bio) VALUES (last_insert_rowid(), ?, ?, ?)",
                [$employee['name'], $employee['department'], $employee['bio']]
            );
        }
    }

    public function testSQLiteWindowFunctions(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Window functions en SQLite 3.25+
        $result = $qb->windowFunction(
            'row_number',
            '*',
            [],
            ['department'],
            [['column' => 'salary', 'direction' => 'DESC']],
            'salary_rank'
        );

        $this->assertIsArray($result);
        $this->assertNotEmpty($result);
    }

    public function testSQLiteWindowFunctionLag(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // LAG function en SQLite
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

    public function testSQLiteJSONOperations(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // JSON operations con json_extract
        $result = $qb->jsonOperation('extract', 'profile', '$.level');

        $this->assertIsArray($result);
        $this->assertNotEmpty($result);
    }

    public function testSQLiteJSONPathQuery(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Extraer array de skills
        $result = $qb->jsonOperation('extract', 'profile', '$.skills[0]');

        $this->assertIsArray($result);
    }

    public function testSQLiteCTESimple(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // CTE simple en SQLite
        $result = $qb->withCte([
            'dept_summary' => [
                'query' => 'SELECT department, COUNT(*) as emp_count, AVG(salary) as avg_salary FROM employees GROUP BY department',
                'bindings' => []
            ]
        ], 'SELECT * FROM dept_summary WHERE emp_count > 1', []);

        $this->assertIsArray($result);
    }

    public function testSQLiteRecursiveCTE(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // CTE recursivo para generar series
        $result = $qb->withCte([
            'salary_series' => [
                'query' => 'WITH RECURSIVE series(x) AS (
                    SELECT 50000
                    UNION ALL
                    SELECT x + 5000 FROM series WHERE x < 100000
                ) SELECT * FROM series',
                'bindings' => []
            ]
        ], 'SELECT s.x as salary_level, COUNT(e.id) as employee_count
            FROM salary_series s
            LEFT JOIN employees e ON e.salary >= s.x AND e.salary < s.x + 5000
            GROUP BY s.x', []);

        $this->assertIsArray($result);
    }

    public function testSQLiteFullTextSearchFTS5(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees_fts');

        // Full-text search con FTS5
        $result = $qb->fullTextSearch(['bio'], 'SQLite database', [
            'fts_version' => 'fts5',
            'match_operator' => 'MATCH',
            'highlight' => true
        ]);

        $this->assertIsArray($result);
    }

    public function testSQLiteUnionOperations(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // UNION con queries diferentes
        $engineeringQuery = [
            'sql' => 'SELECT name, department, salary FROM employees WHERE department = ?',
            'bindings' => ['Engineering']
        ];

        $analyticsQuery = [
            'sql' => 'SELECT name, department, salary FROM employees WHERE department = ?',
            'bindings' => ['Analytics']
        ];

        $result = $qb->union([$engineeringQuery, $analyticsQuery], false);
        $this->assertIsArray($result);
    }

    public function testSQLiteAdvancedAggregations(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Agregaciones estadísticas en SQLite
        $result = $qb->advancedAggregation('median', 'salary', []);

        $this->assertIsArray($result);
    }

    public function testSQLiteQueryOptimization(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Optimización de consulta específica para SQLite
        $result = $qb->optimizeQuery([
            'analyze_table' => true,
            'suggest_indexes' => true,
            'explain_query_plan' => true
        ]);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('optimization_suggestions', $result);
    }

    public function testSQLiteDriverCapabilities(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Verificar capacidades específicas de SQLite
        $capabilities = $qb->getDriverCapabilities();

        $this->assertIsArray($capabilities);
        $this->assertArrayHasKey('version', $capabilities);
        $this->assertArrayHasKey('features', $capabilities);
        $this->assertArrayHasKey('window_functions', $capabilities['features']);
        $this->assertArrayHasKey('json_support', $capabilities['features']);
        $this->assertArrayHasKey('fts_support', $capabilities['features']);
    }

    public function testSQLiteDriverLimits(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Obtener límites específicos de SQLite
        $limits = $qb->getDriverLimits();

        $this->assertIsArray($limits);
        $this->assertArrayHasKey('max_columns', $limits);
        $this->assertArrayHasKey('max_sql_length', $limits);
        $this->assertArrayHasKey('max_page_size', $limits);
    }

    protected function tearDown(): void
    {
        // En SQLite :memory:, no necesitamos limpiar explícitamente
        // La base de datos se destruye automáticamente
    }
}
