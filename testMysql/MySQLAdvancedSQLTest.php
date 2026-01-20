<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

/**
 * Tests específicos para funcionalidades SQL avanzadas de MySQL.
 *
 * Estas pruebas verifican:
 * - Window functions específicas de MySQL
 * - JSON operations con sintaxis MySQL (->, ->>)
 * - Full-text search con FULLTEXT indexes
 * - Query hints específicos de MySQL
 */
/**
 * @group mysql
 */
class MySQLAdvancedSQLTest extends TestCase
{
    private ?VersaORM $orm = null;

    private ?QueryBuilder $queryBuilder = null;

    protected function setUp(): void
    {
        // Configuración específica para MySQL
        $config = [
            'engine' => 'pdo',
            'driver' => 'mysql',
            'host' => getenv('DB_HOST') ?: 'localhost',
            'port' => (int) (getenv('DB_PORT') ?: 3306),
            'database' => getenv('DB_NAME') ?: 'versaorm_test',
            'username' => getenv('DB_USER') ?: 'local',
            'password' => getenv('DB_PASS') ?: 'local',
            'options' => [
                'charset' => 'utf8mb4',
                'sql_mode' => 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO',
            ],
        ];

        $this->orm = new VersaORM($config);
        // Usar un nombre de tabla único para evitar colisiones con otras pruebas que también usan 'employees'
        $this->queryBuilder = new QueryBuilder($this->orm, 'employees_mysql_adv');

        $this->createMySQLTestTables();
    }

    protected function tearDown(): void
    {
        // Limpiar tabla después de cada test
        $this->orm->exec('DROP TABLE IF EXISTS employees_mysql_adv');
    }

    public function test_my_sql_window_function_with_specific_syntax(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees_mysql_adv');

        $result = $qb->windowFunction(
            'row_number',
            '*',
            [],
            ['department'],
            [['column' => 'salary', 'direction' => 'DESC']],
            'row_num',
        );

        static::assertIsArray($result);
        static::assertNotEmpty($result);

        // Verificar que MySQL maneja correctamente las window functions
        static::assertArrayHasKey('row_num', $result[0] ?? []);
    }

    public function test_my_sqljson_operations_with_arrow_syntax(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees_mysql_adv');

        // Usar sintaxis específica de MySQL para JSON
        $result = $qb->jsonOperation('extract', 'profile', '$.skills[0]');

        static::assertIsArray($result);
        static::assertNotEmpty($result);
    }

    public function test_my_sql_full_text_search_with_match(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees_mysql_adv');

        // Full-text search específico de MySQL
        $result = $qb->fullTextSearch(['bio'], 'PHP developer', [
            'mode' => 'NATURAL LANGUAGE',
            'with_score' => true,
        ]);

        static::assertIsArray($result);
    }

    public function test_my_sql_query_hints(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees_mysql_adv');

        // Hints específicos de MySQL
        $qb->queryHints([
            'USE_INDEX' => 'idx_department',
            'SQL_CALC_FOUND_ROWS' => true,
        ]);

        $result = $qb->where('department', '=', 'Engineering')->get();
        static::assertIsArray($result);
    }

    public function test_my_sql_advanced_aggregation_group_concat(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees_mysql_adv');

        // GROUP_CONCAT específico de MySQL
        $result = $qb->advancedAggregation('group_concat', 'name', [
            'separator' => ', ',
            'order_by' => 'salary DESC',
        ]);

        static::assertIsArray($result);
    }

    public function test_my_sqlcte_with_recursive(): void
    {
        $qb = new QueryBuilder($this->orm, 'employees_mysql_adv');

        // CTE recursivo en MySQL 8.0+
        $result = $qb->withCte(
            [
                'salary_levels' => [
                    'query' => 'SELECT department, AVG(salary) as avg_salary FROM employees_mysql_adv GROUP BY department',
                    'bindings' => [],
                ],
            ],
            'SELECT * FROM salary_levels WHERE avg_salary > 75000',
            [],
        );

        static::assertIsArray($result);
    }

    private function createMySQLTestTables(): void
    {
        // Tabla con full-text index para MySQL
        $this->orm->exec(
            "\n            CREATE TABLE IF NOT EXISTS employees_mysql_adv (\n                id INT AUTO_INCREMENT PRIMARY KEY,\n                name VARCHAR(255) NOT NULL,\n                department VARCHAR(100),\n                salary DECIMAL(10,2),\n                hire_date DATE,\n                profile JSON,\n                bio TEXT,\n                INDEX idx_department (department),\n                FULLTEXT(bio)\n            ) ENGINE=InnoDB\n        ",
        );

        // Insertar datos de prueba
        $employees = [
            [
                'name' => 'Alice Johnson',
                'department' => 'Engineering',
                'salary' => 90000.00,
                'hire_date' => '2020-01-15',
                'profile' => '{"skills": ["PHP", "MySQL"], "level": "senior"}',
                'bio' => 'Senior PHP developer with expertise in database optimization',
            ],
            [
                'name' => 'Bob Smith',
                'department' => 'Engineering',
                'salary' => 85000.00,
                'hire_date' => '2019-03-10',
                'profile' => '{"skills": ["JavaScript", "React"], "level": "mid"}',
                'bio' => 'Frontend developer specializing in React applications',
            ],
            [
                'name' => 'Carol Williams',
                'department' => 'Marketing',
                'salary' => 70000.00,
                'hire_date' => '2021-06-20',
                'profile' => '{"skills": ["Content", "SEO"], "level": "senior"}',
                'bio' => 'Marketing expert with focus on content strategy and SEO',
            ],
        ];

        foreach ($employees as $employee) {
            // Usar QueryBuilder/ORM para insertar y ejercitar el ORM
            $this->orm->table('employees_mysql_adv')->insert($employee);
        }
    }
}
