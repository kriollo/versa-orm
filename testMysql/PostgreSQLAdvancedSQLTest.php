<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

/**
 * Tests específicos para funcionalidades SQL avanzadas de PostgreSQL
 *
 * Estas pruebas verifican:
 * - Array operations específicas de PostgreSQL
 * - JSONB operations avanzadas
 * - Full-text search con tsvector y tsquery
 * - CTEs recursivos complejos
 */
class PostgreSQLAdvancedSQLTest extends TestCase
{
    private VersaORM $orm;
    private QueryBuilder $queryBuilder;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_pgsql')) {
            $this->markTestSkipped('pdo_pgsql no está disponible en este entorno');
        }
        // Configuración específica para PostgreSQL
        $config = [
            'driver' => 'postgresql',
            'host' => 'localhost',
            'port' => 5432,
            'database' => 'test_versa_orm',
            'username' => 'postgres',
            'password' => '',
            'options' => [
                'sslmode' => 'prefer',
            ]
        ];

        $this->orm = new VersaORM($config);
        $this->queryBuilder = new QueryBuilder($this->orm, 'employees');

        $this->createPostgreSQLTestTables();
    }

    private function createPostgreSQLTestTables(): void
    {
        // Tabla con tipos específicos de PostgreSQL
        $this->orm->exec("
            CREATE TABLE IF NOT EXISTS employees (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                department VARCHAR(100),
                salary DECIMAL(10,2),
                hire_date DATE,
                profile JSONB,
                skills TEXT[],
                bio TEXT,
                search_vector TSVECTOR
            )
        ");

        // Crear índices específicos de PostgreSQL
        $this->orm->exec("CREATE INDEX IF NOT EXISTS idx_profile_gin ON employees USING GIN(profile)");
        $this->orm->exec("CREATE INDEX IF NOT EXISTS idx_skills_gin ON employees USING GIN(skills)");
        $this->orm->exec("CREATE INDEX IF NOT EXISTS idx_search_gin ON employees USING GIN(search_vector)");

        // Insertar datos de prueba con tipos PostgreSQL
        $employees = [
            [
                'name' => 'Alice Johnson',
                'department' => 'Engineering',
                'salary' => 90000.00,
                'hire_date' => '2020-01-15',
                'profile' => '{"skills": ["PHP", "PostgreSQL"], "level": "senior", "certifications": ["AWS", "Docker"]}',
                'skills' => '{"PHP", "PostgreSQL", "Docker"}',
                'bio' => 'Senior database engineer with PostgreSQL expertise'
            ],
            [
                'name' => 'Bob Smith',
                'department' => 'Engineering',
                'salary' => 85000.00,
                'hire_date' => '2019-03-10',
                'profile' => '{"skills": ["Python", "Django"], "level": "mid", "certifications": ["GCP"]}',
                'skills' => '{"Python", "Django", "PostgreSQL"}',
                'bio' => 'Backend developer specializing in Python and PostgreSQL'
            ],
            [
                'name' => 'Carol Williams',
                'department' => 'Data Science',
                'salary' => 95000.00,
                'hire_date' => '2021-06-20',
                'profile' => '{"skills": ["R", "Statistics"], "level": "senior", "certifications": ["Tableau"]}',
                'skills' => '{"R", "Statistics", "PostgreSQL", "Tableau"}',
                'bio' => 'Data scientist with advanced PostgreSQL analytics'
            ]
        ];

        foreach ($employees as $employee) {
            $this->orm->exec(
                "INSERT INTO employees (name, department, salary, hire_date, profile, skills, bio, search_vector)
                 VALUES (?, ?, ?, ?, ?::jsonb, ?::text[], ?, to_tsvector('english', ?))",
                [
                    $employee['name'],
                    $employee['department'],
                    $employee['salary'],
                    $employee['hire_date'],
                    $employee['profile'],
                    $employee['skills'],
                    $employee['bio'],
                    $employee['bio']
                ]
            );
        }
    }

    public function testPostgreSQLArrayOperations(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Operación de array específica de PostgreSQL
        $result = $qb->arrayOperations('contains', 'skills', 'PHP');

        $this->assertIsArray($result);
        $this->assertNotEmpty($result);
    }

    public function testPostgreSQLArrayOverlap(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Array overlap operation
        $result = $qb->arrayOperations('overlap', 'skills', ['PHP', 'Python']);

        $this->assertIsArray($result);
    }

    public function testPostgreSQLJSONBOperations(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // JSONB operations específicas de PostgreSQL
        $result = $qb->jsonOperation('contains', 'profile', '{"level": "senior"}');

        $this->assertIsArray($result);
    }

    public function testPostgreSQLJSONBPathQueries(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // JSONB path queries
        $result = $qb->jsonOperation('extract', 'profile', '$.certifications[0]');

        $this->assertIsArray($result);
    }

    public function testPostgreSQLFullTextSearchWithTSVector(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Full-text search con tsvector
        $result = $qb->fullTextSearch(['search_vector'], 'PostgreSQL & developer', [
            'language' => 'english',
            'operator' => '@@',
            'rank' => true
        ]);

        $this->assertIsArray($result);
    }

    public function testPostgreSQLWindowFunctionsAdvanced(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Window functions avanzadas de PostgreSQL
        $result = $qb->windowFunction(
            'lag',
            'salary',
            ['offset' => 2, 'default_value' => 0],
            ['department'],
            [['column' => 'hire_date', 'direction' => 'ASC']],
            'prev_salary_2'
        );

        $this->assertIsArray($result);
    }

    public function testPostgreSQLRecursiveCTE(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // CTE recursivo complejo para jerarquía organizacional
        $result = $qb->withCte([
            'dept_hierarchy' => [
                'query' => 'WITH RECURSIVE dept_tree AS (
                    SELECT department, department as root_dept, 1 as level
                    FROM employees WHERE department = ?
                    UNION ALL
                    SELECT e.department, dt.root_dept, dt.level + 1
                    FROM employees e
                    JOIN dept_tree dt ON e.department != dt.department
                    WHERE dt.level < 3
                ) SELECT * FROM dept_tree',
                'bindings' => ['Engineering']
            ]
        ], 'SELECT * FROM dept_hierarchy ORDER BY level', []);

        $this->assertIsArray($result);
    }

    public function testPostgreSQLAdvancedAggregations(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees');

        // Agregaciones estadísticas avanzadas
        $result = $qb->advancedAggregation('percentile', 'salary', [
            'percentile' => 0.95,
            'method' => 'cont'  // percentile_cont
        ]);

        $this->assertIsArray($result);
    }

    public function testPostgreSQLIntersectAndExcept(): void
    {
        $qb1 = new QueryBuilder($this->orm, 'employees');
        $qb1->where('department', '=', 'Engineering');

        $qb2 = new QueryBuilder($this->orm, 'employees');
        $qb2->where('salary', '>', 80000);

        // INTERSECT operation
        $result = $qb1->intersect($qb2);
        $this->assertIsArray($result);

        // EXCEPT operation
        $result = $qb1->except($qb2);
        $this->assertIsArray($result);
    }

    protected function tearDown(): void
    {
        // Limpiar tabla después de cada test
        $this->orm->exec("DROP TABLE IF EXISTS employees");
    }
}
