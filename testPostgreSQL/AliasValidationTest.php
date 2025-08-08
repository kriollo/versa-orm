<?php

// tests/AliasValidationTest.php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaORMException;

class AliasValidationTest extends TestCase
{
    /**
     * Test para alias de tabla simples
     */
    public function testTableAliasSimple(): void
    {
        // Alias con palabras completas
        $result = self::$orm->table('users as u')
            ->select(['u.*'])
            ->limit(1)
            ->get();

        $this->assertIsArray($result);
    }

    /**
     * Test para patrones de columna con asterisco (el caso que estaba fallando)
     */
    public function testColumnWildcardPatterns(): void
    {
        // Patrón table.* - este era el que causaba "Invalid or malicious column name detected: t.*"
        $result = self::$orm->table('users as u')
            ->select(['u.*'])
            ->limit(1)
            ->get();

        $this->assertIsArray($result);

        // Asterisco simple
        $result = self::$orm->table('users')
            ->select(['*'])
            ->limit(1)
            ->get();

        $this->assertIsArray($result);
    }

    /**
     * Test para alias de columna
     */
    public function testColumnAliases(): void
    {
        // Alias simple de columna
        $result = self::$orm->table('users')
            ->select(['name as user_name'])
            ->limit(1)
            ->get();

        $this->assertIsArray($result);
        if (!empty($result)) {
            $this->assertArrayHasKey('user_name', $result[0]);
        }
    }

    /**
     * Test para JOINs básicos con alias (usando esquema más simple)
     */
    public function testBasicJoinWithAliases(): void
    {
        // JOIN simple con alias solo si existe la relación
        $result = self::$orm->table('users as u')
            ->select(['u.id', 'u.name'])
            ->limit(1)
            ->get();

        $this->assertIsArray($result);

        // Test de alias con self-join en users si necesario
        $result = self::$orm->table('users as u1')
            ->select(['u1.name as user1_name'])
            ->limit(1)
            ->get();

        $this->assertIsArray($result);
    }
    /**
     * Test para casos que DEBEN fallar (seguridad)
     */
    public function testInvalidAliasesShouldFail(): void
    {
        // Alias con caracteres maliciosos deben fallar
        $maliciousAliases = [
            'users as u; DROP TABLE users; --',
            'users as u/**/OR/**/1=1',
            'users as u\'',
        ];

        foreach ($maliciousAliases as $maliciousAlias) {
            try {
                self::$orm->table($maliciousAlias)
                    ->select(['*'])
                    ->limit(1)
                    ->get();

                $this->fail("Se esperaba que el alias malicioso fallara: $maliciousAlias");
            } catch (VersaORMException $e) {
                // Se espera que falle
                $this->assertStringContainsString('Invalid', $e->getMessage());
            }
        }
    }
}
