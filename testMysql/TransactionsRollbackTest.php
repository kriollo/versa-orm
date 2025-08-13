<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * Pruebas de transacciones: commit y rollback usando las APIs del ORM/QueryBuilder.
 */
/**
 * @group mysql
 */
class TransactionsRollbackTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $config = [
            'engine'   => 'pdo',
            'driver'   => 'mysql',
            'host'     => 'localhost',
            'port'     => 3306,
            'database' => 'versaorm_test',
            'username' => 'local',
            'password' => 'local',
        ];
        $this->orm = new VersaORM($config);

        // Asegurar tabla de pruebas aislada
        $this->orm->exec('DROP TABLE IF EXISTS tx_users');
        $this->orm->exec('CREATE TABLE tx_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(191) UNIQUE NOT NULL
        ) ENGINE=InnoDB');
    }

    protected function tearDown(): void
    {
        $this->orm->exec('DROP TABLE IF EXISTS tx_users');
    }

    public function testCommitPersistsChanges(): void
    {
        $this->orm->beginTransaction();
        $this->orm->table('tx_users')->insert(['name' => 'Tx Commit', 'email' => 'tx.commit@example.com']);
        $this->orm->commit();

        $found = $this->orm->table('tx_users')->where('email', '=', 'tx.commit@example.com')->findOne();
        self::assertNotNull($found);
        self::assertSame('Tx Commit', $found->name);
    }

    public function testRollbackRevertsChanges(): void
    {
        // Estado inicial vacío
        $pre = $this->orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        self::assertNull($pre);

        // Iniciar transacción y generar un cambio
        $this->orm->beginTransaction();
        $this->orm->table('tx_users')->insert(['name' => 'Tx Rollback', 'email' => 'tx.rollback@example.com']);

        // Verificar que el cambio se ve dentro de la transacción (si el aislamiento lo permite)
        $mid = $this->orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        self::assertNotNull($mid);

        // Revertir
        $this->orm->rollBack();

        // Debe no existir al final
        $post = $this->orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        self::assertNull($post);
    }
}
