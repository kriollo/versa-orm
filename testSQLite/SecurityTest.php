<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaORMException;

use function count;

/**
 * Subconjunto de tests de seguridad para SQLite (validación de inyección y sanitización básica).
 */
class SecurityTest extends TestCase
{
    public function test_sql_injection_in_where_clause(): void
    {
        $malicious = "' OR 1=1 --";
        $users = self::$orm->table('users')->where('email', '=', $malicious)->getAll();
        static::assertCount(0, $users);
    }

    public function test_sql_injection_boolean_attack(): void
    {
        foreach (["' OR 1=1--", "' OR 'a'='a"] as $attack) {
            $users = self::$orm->table('users')->where('email', '=', $attack)->getAll();
            static::assertCount(0, $users, 'Boolean injection no bloqueada');
        }
    }

    public function test_malicious_table_names(): void
    {
        foreach (['users; DROP TABLE posts;', 'table--comment', "users'name"] as $tbl) {
            try {
                self::$orm->table($tbl)->count();
                static::fail('Nombre de tabla malicioso aceptado: ' . $tbl);
            } catch (VersaORMException $e) {
                static::assertStringContainsString('error', strtolower($e->getMessage()));
            }
        }
    }

    public function test_malicious_column_names(): void
    {
        foreach (['id;DROP', 'col--x', "field'name"] as $col) {
            try {
                self::$orm->table('users')->select([$col])->count();
                static::fail('Nombre de columna malicioso aceptado: ' . $col);
            } catch (VersaORMException $e) {
                static::assertStringContainsString('invalid or malicious column name', strtolower($e->getMessage()));
            }
        }
    }

    public function test_order_by_injection(): void
    {
        try {
            self::$orm->table('users')->orderBy('id; DROP TABLE users;', 'asc')->count();
            static::fail('ORDER BY malicioso aceptado');
        } catch (VersaORMException $e) {
            static::assertStringContainsString('invalid or malicious column name', strtolower($e->getMessage()));
        }
    }

    public function test_limit_casting(): void
    {
        $one = self::$orm->table('users')->limit('1')->getAll();
        static::assertLessThanOrEqual(1, count($one));
    }

    public function test_bind_parameter_injection(): void
    {
        foreach (["'; DROP TABLE users; --", "1' UNION SELECT"] as $bind) {
            $res = self::$orm->exec('SELECT * FROM users WHERE email = ?', [$bind]);
            static::assertIsArray($res);
            static::assertCount(0, $res);
        }
    }

    public function test_null_byte_injection(): void
    {
        $attack = "admin\x00'; DROP TABLE users; --";
        $users = self::$orm->table('users')->where('name', '=', $attack)->getAll();
        static::assertCount(0, $users);
    }
}
