<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\Tests\PostgreSQL\TestCase;

/**
 * Pruebas de transacciones: commit y rollback usando las APIs del ORM/QueryBuilder.
 */
class TransactionsRollbackTest extends TestCase
{
    protected function setUp(): void
    {
        // No llamamos a parent::setUp() para evitar recrear el esquema base; este test usa su propia tabla
        $driver = self::$orm->getConfig()['driver'] ?? '';
        if ($driver !== 'mysql') {
            $this->markTestSkipped('TransactionsRollbackTest es específico de MySQL; omitido en suite PostgreSQL');
        }

        // Asegurar tabla de pruebas aislada
        self::$orm->exec('DROP TABLE IF EXISTS tx_users');
        self::$orm->exec('CREATE TABLE tx_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(191) UNIQUE NOT NULL
        ) ENGINE=InnoDB');
    }

    protected function tearDown(): void
    {
        try {
            self::$orm->exec('DROP TABLE IF EXISTS tx_users');
        } catch (\Throwable $e) {
        }
    }

    public function testCommitPersistsChanges(): void
    {
        self::$orm->beginTransaction();
        self::$orm->table('tx_users')->insert(['name' => 'Tx Commit', 'email' => 'tx.commit@example.com']);
        self::$orm->commit();

        $found = self::$orm->table('tx_users')->where('email', '=', 'tx.commit@example.com')->findOne();
        $this->assertNotNull($found);
        $this->assertEquals('Tx Commit', $found->name);
    }

    public function testRollbackRevertsChanges(): void
    {
        // Estado inicial vacío
        $pre = self::$orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        $this->assertNull($pre);

        // Iniciar transacción y generar un cambio
        self::$orm->beginTransaction();
        self::$orm->table('tx_users')->insert(['name' => 'Tx Rollback', 'email' => 'tx.rollback@example.com']);

        // Verificar que el cambio se ve dentro de la transacción (si el aislamiento lo permite)
        $mid = self::$orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        $this->assertNotNull($mid);

        // Revertir
        self::$orm->rollBack();

        // Debe no existir al final
        $post = self::$orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        $this->assertNull($post);
    }
}
