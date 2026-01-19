<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaORMException;

use function count;

/**
 * Tests de Seguridad para VersaORM-PHP (PostgreSQL).
 *
 * @group postgresql
 */
class SecurityTest extends TestCase
{
    // ======================================================================
    // SQL INJECTION TESTS - WHERE CLAUSES
    // ======================================================================

    public function test_sql_injection_in_where_clause(): void
    {
        $maliciousInput = "' OR 1=1 --";
        $users = self::$orm->table('users')->where('email', '=', $maliciousInput)->getAll();

        self::assertCount(0, $users, 'SQL injection attempt in WHERE clause was not prevented.');
    }

    public function test_sql_injection_union_attack(): void
    {
        $unionAttack = "999' UNION SELECT password FROM users WHERE '1'='1";

        try {
            $users = self::$orm->table('users')->where('id', '=', $unionAttack)->getAll();
            self::assertCount(0, $users, 'UNION-based SQL injection was not prevented.');
        } catch (VersaORMException $e) {
            // Postgres throws invalid text representation for integer column
            self::assertStringContainsString('invalid', strtolower($e->getMessage()));
        }
    }

    public function test_sql_injection_boolean_attack(): void
    {
        $booleanAttacks = [
            "' OR 1=1--",
            "' OR 'a'='a",
            "' OR true--",
            "admin' AND 1=1--",
        ];

        foreach ($booleanAttacks as $attack) {
            $users = self::$orm->table('users')->where('email', '=', $attack)->getAll();
            self::assertCount(0, $users, "Boolean SQL injection was not prevented for: {$attack}");
        }
    }

    public function test_sql_injection_stacked_queries(): void
    {
        $stackedAttacks = [
            "'; INSERT INTO users (name, email) VALUES ('hacker', 'hacker@example.com'); --",
            "'; UPDATE users SET status='admin' WHERE id=1; --",
            "'; DROP TABLE users; --",
        ];

        foreach ($stackedAttacks as $attack) {
            $users = self::$orm->table('users')->where('name', '=', $attack)->getAll();
            self::assertCount(0, $users, "Stacked query injection was not prevented for: {$attack}");
        }
    }

    // ======================================================================
    // SQL INJECTION TESTS - WHERE RAW CLAUSES
    // ======================================================================

    public function test_where_raw_with_proper_parameterization(): void
    {
        $users = self::$orm->table('users')->whereRaw('LOWER(name) = ?', ['alice'])->findAll();
        self::assertCount(1, $users, 'Properly parameterized whereRaw should work.');
    }

    public function test_where_raw_injection_prevention(): void
    {
        $maliciousInput = '999=999; DROP TABLE users;';

        try {
            $users = self::$orm->table('users')->whereRaw('id = ?', [$maliciousInput])->getAll();
            self::assertCount(0, $users, 'whereRaw injection was not prevented.');
        } catch (VersaORMException $e) {
            self::assertStringContainsString('error', strtolower($e->getMessage()));
        }
    }

    // ======================================================================
    // IDENTIFIER VALIDATION TESTS
    // ======================================================================

    public function test_malicious_table_names(): void
    {
        $maliciousTableNames = [
            'users; DROP DATABASE test;',
            'table--comment',
            "users'name",
            'table/*comment*/',
            '../../etc/passwd',
            "<script>alert('xss')</script>",
            '$(rm -rf /)',
        ];

        foreach ($maliciousTableNames as $tableName) {
            try {
                self::$orm->table($tableName)->getAll();
                self::fail("Malicious table name '{$tableName}' should have been rejected.");
            } catch (VersaORMException $e) {
                self::assertStringContainsString('error', strtolower($e->getMessage()));
            }
        }
    }

    public function test_malicious_column_names(): void
    {
        $maliciousColumns = [
            'id; DROP TABLE users;',
            'column--comment',
            "field'name",
            'name/**/',
            'col WITH GRANT OPTION',
        ];

        foreach ($maliciousColumns as $column) {
            try {
                self::$orm->table('users')->select([$column])->getAll();
                self::fail("Malicious column name '{$column}' should have been rejected.");
            } catch (VersaORMException $e) {
                self::assertStringContainsString('invalid or malicious column name', strtolower($e->getMessage()));
            }
        }
    }

    public function test_safe_identifiers(): void
    {
        $safeIdentifiers = [
            'users',
            'posts',
            'table123',
            'column_name_with_underscores',
            'ID',
            'created_at',
        ];

        foreach ($safeIdentifiers as $identifier) {
            try {
                self::$orm->table($identifier)->count();
            } catch (VersaORMException $e) {
                // Postgres might say "relation does not exist" or "table does not exist" or "no existe la relación"
                $msg = strtolower($e->getMessage());
                self::assertTrue(
                    str_contains($msg, 'not exist')
                    || str_contains($msg, 'no existe')
                    || str_contains($msg, 'relation')
                    || str_contains($msg, 'relación'),
                    'Error message should indicate missing relation: ' . $msg,
                );
            }
        }
    }

    // ======================================================================
    // ORDER BY, LIMIT, OFFSET INJECTION TESTS
    // ======================================================================

    public function test_order_by_injection(): void
    {
        $maliciousOrderBy = 'id; DROP TABLE users;';

        try {
            self::$orm->table('users')->orderBy($maliciousOrderBy, 'asc')->getAll();
            self::fail('Malicious ORDER BY should have been rejected.');
        } catch (VersaORMException $e) {
            self::assertStringContainsString('invalid or malicious column name', strtolower($e->getMessage()));
        }
    }

    public function test_limit_injection(): void
    {
        $users = self::$orm->table('users')->limit(1)->getAll();
        self::assertCount(1, $users);

        $users = self::$orm->table('users')->limit('2')->getAll();
        self::assertLessThanOrEqual(2, count($users));
    }

    // ======================================================================
    // INSERT/UPDATE DATA SANITIZATION TESTS
    // ======================================================================

    public function test_xss_in_insert_data(): void
    {
        $xssPayloads = [
            '<script>alert("xss")</script>',
            'javascript:alert("xss")',
            '<img src=x onerror=alert("xss")>',
            '"; alert("xss"); --',
        ];

        foreach ($xssPayloads as $payload) {
            $id = self::$orm
                ->table('users')
                ->insertGetId([
                    'name' => 'XSS Test User',
                    'email' => 'xss' . mt_rand() . '@example.com',
                    'status' => $payload,
                ]);

            $user = self::$orm->table('users')->find($id);
            self::assertSame($payload, $user->status, 'XSS input should be stored as-is');

            self::$orm->table('users')->where('id', '=', $id)->delete();
        }
    }

    // ======================================================================
    // BIND PARAMETER SECURITY TESTS
    // ======================================================================

    public function test_bind_parameter_injection(): void
    {
        $maliciousBinds = [
            "'; DROP TABLE users; --",
            "admin' OR '1'='1",
            "1' UNION SELECT password FROM users --",
        ];

        foreach ($maliciousBinds as $bind) {
            $result = self::$orm->exec('SELECT * FROM users WHERE email = ?', [$bind]);
            self::assertIsArray($result);
            self::assertCount(0, $result);
        }
    }

    // ======================================================================
    // TRANSACTION SECURITY TESTS
    // ======================================================================

    public function test_transaction_injection_prevention(): void
    {
        try {
            self::$orm->exec('BEGIN');

            $maliciousInput = "'; COMMIT; DROP TABLE users; BEGIN; --";
            $users = self::$orm->table('users')->where('name', '=', $maliciousInput)->getAll();

            self::assertCount(0, $users, 'Transaction injection was not prevented.');

            self::$orm->exec('ROLLBACK');
        } catch (VersaORMException $e) {
            self::assertStringContainsString('error', strtolower($e->getMessage()));
        }
    }

    public function test_null_byte_injection(): void
    {
        $nullByteAttack = "admin\x00'; DROP TABLE users; --";
        $users = self::$orm->table('users')->where('name', '=', $nullByteAttack)->getAll();
        self::assertCount(0, $users);
    }
}
