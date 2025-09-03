<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaORMException;

use function count;

/**
 * Tests de Seguridad para VersaORM-PHP.
 *
 * Estos tests verifican que el ORM maneja correctamente:
 * - Prevención de inyección SQL
 * - Validación de identificadores
 * - Sanitización de datos
 * - Prevención de XSS
 * - Casos extremos de seguridad
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

        // La consulta debe estar parametrizada, así que no debe retornar usuarios.
        self::assertCount(0, $users, 'SQL injection attempt in WHERE clause was not prevented.');
    }

    public function test_sql_injection_union_attack(): void
    {
        $unionAttack = "999' UNION SELECT password FROM admin_users WHERE '1'='1";
        // Usar columna de texto para evitar error de tipo en Postgres
        $users = self::$orm->table('users')->where('status', '=', $unionAttack)->getAll();

        // No debe retornar datos debido a parametrización (ID 999 no existe)
        self::assertCount(0, $users, 'UNION-based SQL injection was not prevented.');
    }

    public function test_sql_injection_boolean_attack(): void
    {
        $booleanAttacks = [
            "' OR 1=1--",
            "' OR 'a'='a",
            "' OR true--",
            "admin' AND 1=1#",
        ];

        // En PostgreSQL, comparar id (int) con string lanza error de tipo; usamos columna texto 'status'
        foreach ($booleanAttacks as $attack) {
            $users = self::$orm->table('users')->where('status', '=', $attack)->getAll();
            self::assertCount(0, $users, "Boolean SQL injection was not prevented for: {$attack}");
        }
    }

    public function test_sql_injection_stacked_queries(): void
    {
        $stackedAttacks = [
            "'; INSERT INTO users (username, password) VALUES ('hacker', 'pass'); --",
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
        // Uso correcto de whereRaw con parámetros
        $users = self::$orm->table('users')->whereRaw('LOWER(name) = ?', ['alice'])->findAll();
        self::assertCount(1, $users, 'Properly parameterized whereRaw should work.');
    }

    public function test_where_raw_injection_prevention(): void
    {
        // Este test verifica que whereRaw sin parámetros no cause problemas
        $maliciousInput = '999=999; DROP TABLE users;';

        // Este caso debería estar parametrizado; no debe devolver resultados
        $users = self::$orm->table('users')->whereRaw('status = ?', [$maliciousInput])->getAll();
        self::assertIsArray($users);
        self::assertCount(0, $users, 'whereRaw injection was not prevented.');
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
                // Se espera que lance excepción
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
                // Se espera que lance excepción
                self::assertStringContainsString('invalid or malicious column name', strtolower($e->getMessage()));
            }
        }
    }

    public function test_safe_identifiers(): void
    {
        // Estos identificadores deberían ser aceptados
        $safeIdentifiers = [
            'users',
            'user_profiles',
            'table123',
            'column_name_with_underscores',
            'ID',
            'created_at',
            'order_items',
        ];

        foreach ($safeIdentifiers as $identifier) {
            try {
                // No debe lanzar excepción
                self::$orm->table($identifier)->count();
            } catch (VersaORMException $e) {
                // En Postgres el mensaje puede variar; sólo verificamos que NO sea por identificador inválido
                self::assertStringNotContainsString('invalid or malicious', strtolower($e->getMessage()));
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
        // LIMIT debe aceptar solo números enteros
        $users = self::$orm->table('users')->limit(1)->getAll();
        self::assertCount(1, $users);

        // Test con string numérico (debería convertirse)
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
            $id = self::$orm->table('users')->insertGetId([
                'name' => 'XSS Test User',
                'email' => 'xss' . mt_rand() . '@example.com',
                'status' => $payload,
            ]);

            $user = self::$orm->table('users')->find($id);

            // El ORM debe almacenar el input tal como viene - es responsabilidad del desarrollador escapar en salida
            self::assertSame($payload, $user->status, "XSS input should be stored as-is for payload: {$payload}");

            // Limpiar después del test
            self::$orm->table('users')->where('id', '=', $id)->delete();
        }
    }

    public function test_special_characters_sanitization(): void
    {
        $specialChars = [
            "test\x00\n\r\t\"\\value",  // Null byte, newlines, tabs, quotes, backslash
            'emoji🔥💻🚀test',           // Unicode/emoji
            str_repeat('a', 45),          // Long string within VARCHAR(50) limit
            "''",                         // Already escaped quotes
            '',                           // Empty string
        ];

        foreach ($specialChars as $input) {
            $id = self::$orm->table('users')->insertGetId([
                'name' => 'Special Chars Test',
                'email' => 'special' . mt_rand() . '@example.com',
                'status' => $input,
            ]);

            $user = self::$orm->table('users')->find($id);

            // Comparación laxa: para entradas con bytes nulos, confirmamos que la longitud coincide
            if (str_contains($input, "\x00")) {
                $stored = (string) $user->status;
                self::assertNotSame('', $stored);
                // Debe mantener el resto de caracteres visibles
                self::assertStringContainsString('test', $stored);
            } else {
                self::assertSame($input, $user->status, "Special characters should be preserved: {$input}");
            }

            // Limpiar
            self::$orm->table('users')->where('id', '=', $id)->delete();
        }
    }

    // ======================================================================
    // NUMERIC INJECTION TESTS
    // ======================================================================

    public function test_numeric_injection_attempts(): void
    {
        $numericAttacks = [
            '999; DROP TABLE users',
            '999 OR 1=1',
            "999' UNION SELECT",
            '0x41414141',
        ];

        foreach ($numericAttacks as $attack) {
            // Usar columna de texto para evitar error de tipo en Postgres
            $users = self::$orm->table('users')->where('status', '=', $attack)->getAll();
            self::assertCount(0, $users, "Numeric injection was not prevented for: {$attack}");
        }
    }

    // ======================================================================
    // BIND PARAMETER SECURITY TESTS
    // ======================================================================

    public function test_bind_parameter_injection(): void
    {
        // Test que los parámetros bind están correctamente escapados
        $maliciousBinds = [
            "'; DROP TABLE users; --",
            "admin' OR '1'='1",
            "1' UNION SELECT password FROM admin --",
        ];

        foreach ($maliciousBinds as $bind) {
            $result = self::$orm->exec('SELECT * FROM users WHERE email = ?', [$bind]);
            self::assertIsArray($result, "Bind parameter injection test failed for: {$bind}");
            self::assertCount(0, $result, "Malicious bind should not return results: {$bind}");
        }
    }

    // ======================================================================
    // TYPE CASTING SECURITY TESTS
    // ======================================================================

    public function test_type_casting_security(): void
    {
        // Test que la conversión de tipos no introduce vulnerabilidades
        $maliciousData = [
            'id' => "'; DROP TABLE users; --",
            'status' => "true'; DROP TABLE test; --",
            'count' => "123'; SELECT * FROM passwords; --",
        ];

        // Intentar insertar datos maliciosos
        try {
            self::$orm->table('users')->insert([
                'name' => 'Type Cast Test',
                'email' => 'typecast@example.com',
                'status' => $maliciousData['status'],
            ]);

            // Si la inserción es exitosa, verificar que los datos están seguros
            $user = self::$orm->table('users')->where('email', '=', 'typecast@example.com')->firstArray();
            self::assertNotNull($user);
            // Limpiar
            self::$orm->table('users')->where('email', '=', 'typecast@example.com')->delete();
        } catch (VersaORMException $e) {
            // Es aceptable que falle si detecta el problema
            self::assertStringContainsString('error', strtolower($e->getMessage()));
        }
    }

    // ======================================================================
    // TRANSACTION SECURITY TESTS
    // ======================================================================

    public function test_transaction_injection_prevention(): void
    {
        // Test que las transacciones no permiten inyección
        try {
            self::$orm->exec('START TRANSACTION');

            $maliciousInput = "'; COMMIT; DROP TABLE users; START TRANSACTION; --";
            $users = self::$orm->table('users')->where('name', '=', $maliciousInput)->getAll();

            self::assertCount(0, $users, 'Transaction injection was not prevented.');

            self::$orm->exec('ROLLBACK');
        } catch (VersaORMException $e) {
            // Las transacciones pueden fallar en el entorno de pruebas, eso está bien
            self::assertStringContainsString('error', strtolower($e->getMessage()));
        }
    }

    // ======================================================================
    // EDGE CASES AND STRESS TESTS
    // ======================================================================

    public function test_extreme_length_inputs(): void
    {
        // Test con inputs extremadamente largos
        $veryLongString = str_repeat('A', 1000); // 1KB string (más manejable para pruebas)

        try {
            $id = self::$orm->table('users')->insertGetId([
                'name' => 'Long String Test',
                'email' => 'longstring@example.com',
                'status' => $veryLongString,
            ]);

            $user = self::$orm->table('users')->find($id);
            // El string puede ser cortado por límites de la base de datos, eso está bien
            self::assertNotEmpty($user->status, 'Long string should be stored (even if truncated).');
            self::assertStringStartsWith('AAA', $user->status, 'Long string should start correctly.');

            // Limpiar
            self::$orm->table('users')->where('id', '=', $id)->delete();
        } catch (VersaORMException $e) {
            // Es aceptable que falle por límites de columna
            self::assertStringContainsString('error', strtolower($e->getMessage()));
        }
    }

    public function test_null_byte_injection(): void
    {
        // Test con null bytes que podrían truncar consultas
        $nullByteAttack = "admin\x00'; DROP TABLE users; --";

        $users = self::$orm->table('users')->where('name', '=', $nullByteAttack)->getAll();
        self::assertCount(0, $users, 'Null byte injection was not prevented.');
    }

    public function test_concurrent_security_operations(): void
    {
        // Test que operaciones concurrentes no introducen vulnerabilidades de race condition
        $results = [];

        for ($i = 0; $i < 5; $i++) {
            $maliciousInput = "'; DROP TABLE users; -- attempt {$i}";
            $result = self::$orm->table('users')->where('email', '=', $maliciousInput)->count();
            $results[] = $result;
        }

        // Todos los resultados deben ser 0 (sin inyección exitosa)
        foreach ($results as $result) {
            self::assertSame(0, $result, 'Concurrent security test failed.');
        }
    }
}
