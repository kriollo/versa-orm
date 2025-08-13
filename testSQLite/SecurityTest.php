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
    public function testSqlInjectionInWhereClause(): void
    {
        $malicious = "' OR 1=1 --";
        $users     = self::$orm->table('users')->where('email', '=', $malicious)->getAll();
        self::assertCount(0, $users);
    }

    public function testSqlInjectionBooleanAttack(): void
    {
        foreach (["' OR 1=1--", "' OR 'a'='a"] as $attack) {
            $users = self::$orm->table('users')->where('email', '=', $attack)->getAll();
            self::assertCount(0, $users, 'Boolean injection no bloqueada');
        }
    }

    public function testMaliciousTableNames(): void
    {
        foreach (['users; DROP TABLE posts;', 'table--comment', "users'name"] as $tbl) {
            try {
                self::$orm->table($tbl)->count();
                self::fail('Nombre de tabla malicioso aceptado: ' . $tbl);
            } catch (VersaORMException $e) {
                self::assertStringContainsString('error', strtolower($e->getMessage()));
            }
        }
    }

    public function testMaliciousColumnNames(): void
    {
        foreach (['id;DROP', 'col--x', "field'name"] as $col) {
            try {
                self::$orm->table('users')->select([$col])->count();
                self::fail('Nombre de columna malicioso aceptado: ' . $col);
            } catch (VersaORMException $e) {
                self::assertStringContainsString('invalid or malicious column name', strtolower($e->getMessage()));
            }
        }
    }

    public function testOrderByInjection(): void
    {
        try {
            self::$orm->table('users')->orderBy('id; DROP TABLE users;', 'asc')->count();
            self::fail('ORDER BY malicioso aceptado');
        } catch (VersaORMException $e) {
            self::assertStringContainsString('invalid or malicious column name', strtolower($e->getMessage()));
        }
    }

    public function testLimitCasting(): void
    {
        $one = self::$orm->table('users')->limit('1')->getAll();
        self::assertLessThanOrEqual(1, count($one));
    }

    public function testBindParameterInjection(): void
    {
        foreach (["'; DROP TABLE users; --", "1' UNION SELECT"] as $bind) {
            $res = self::$orm->exec('SELECT * FROM users WHERE email = ?', [$bind]);
            self::assertIsArray($res);
            self::assertCount(0, $res);
        }
    }

    public function testNullByteInjection(): void
    {
        $attack = "admin\x00'; DROP TABLE users; --";
        $users  = self::$orm->table('users')->where('name', '=', $attack)->getAll();
        self::assertCount(0, $users);
    }
}
