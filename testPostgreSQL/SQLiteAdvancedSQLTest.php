<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\QueryBuilder;

/**
 * Pruebas avanzadas específicas de SQLite usando el TestCase unificado.
 * Se omiten automáticamente si el driver activo no es sqlite.
 */
class SQLiteAdvancedSQLTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        global $config;
        $driver = $config['DB']['DB_DRIVER'] ?? '';
        if ($driver !== 'sqlite') {
            $this->markTestSkipped('Pruebas específicas de SQLite, se omiten para driver: ' . $driver);
        }
    }

    private function createSQLiteTestTables(): void
    {
        self::$orm->exec(
            "CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                department TEXT,
                salary REAL,
                hire_date TEXT,
                profile TEXT,
                bio TEXT
            )"
        );

        self::$orm->exec(
            "CREATE VIRTUAL TABLE IF NOT EXISTS employees_fts USING fts5(
                name, department, bio,
                content='employees',
                content_rowid='id'
            )"
        );

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
            self::$orm->exec(
                "INSERT INTO employees (name, department, salary, hire_date, profile, bio) VALUES (?, ?, ?, ?, ?, ?)",
                array_values($employee)
            );

            self::$orm->exec(
                "INSERT INTO employees_fts (rowid, name, department, bio) VALUES (last_insert_rowid(), ?, ?, ?)",
                [$employee['name'], $employee['department'], $employee['bio']]
            );
        }
    }

    public function testSQLiteWindowFunctions(): void
    {
        $this->createSQLiteTestTables();
        $qb = new QueryBuilder(self::$orm, 'employees');
        $result = $qb->windowFunction('row_number', '*', [], ['department'], [[
            'column' => 'salary',
            'direction' => 'DESC'
        ]], 'salary_rank');
        $this->assertIsArray($result);
    }

    public function testSQLiteWindowFunctionLag(): void
    {
        $qb = new QueryBuilder(self::$orm, 'employees');
        $result = $qb->windowFunction('lag', 'salary', ['offset' => 1, 'default_value' => 0], ['department'], [[
            'column' => 'hire_date',
            'direction' => 'ASC'
        ]], 'prev_salary');
        $this->assertIsArray($result);
    }

    public function testSQLiteJSONOperations(): void
    {
        $qb = new QueryBuilder(self::$orm, 'employees');
        $result = $qb->jsonOperation('extract', 'profile', '$.level');
        $this->assertIsArray($result);
    }

    public function testSQLiteJSONPathQuery(): void
    {
        $qb = new QueryBuilder(self::$orm, 'employees');
        $result = $qb->jsonOperation('extract', 'profile', '$.skills[0]');
        $this->assertIsArray($result);
    }

    public function testSQLiteCTESimple(): void
    {
        $qb = new QueryBuilder(self::$orm, 'employees');
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
        $qb = new QueryBuilder(self::$orm, 'employees');
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
        $qb = new QueryBuilder(self::$orm, 'employees_fts');
        $result = $qb->fullTextSearch(['bio'], 'SQLite database', [
            'fts_version' => 'fts5',
            'match_operator' => 'MATCH',
            'highlight' => true
        ]);
        $this->assertIsArray($result);
    }

    public function testSQLiteUnionOperations(): void
    {
        $qb = new QueryBuilder(self::$orm, 'employees');
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
        $qb = new QueryBuilder(self::$orm, 'employees');
        $result = $qb->advancedAggregation('median', 'salary', []);
        $this->assertIsArray($result);
    }

    public function testSQLiteQueryOptimization(): void
    {
        $qb = new QueryBuilder(self::$orm, 'employees');
        $result = $qb->optimizeQuery([
            'analyze_table' => true,
            'suggest_indexes' => true,
            'explain_query_plan' => true
        ]);
        $this->assertIsArray($result);
    }

    public function testSQLiteDriverCapabilities(): void
    {
        $qb = new QueryBuilder(self::$orm, 'employees');
        $capabilities = $qb->getDriverCapabilities();
        $this->assertIsArray($capabilities);
    }

    public function testSQLiteDriverLimits(): void
    {
        $qb = new QueryBuilder(self::$orm, 'employees');
        $limits = $qb->getDriverLimits();
        $this->assertIsArray($limits);
    }

    protected function tearDown(): void
    {
        global $config;
        if (($config['DB']['DB_DRIVER'] ?? '') === 'sqlite') {
            self::$orm->exec('DROP TABLE IF EXISTS employees_fts;');
            self::$orm->exec('DROP TABLE IF EXISTS employees;');
        }
    }
}
