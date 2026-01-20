<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

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
    private ?VersaORM $orm = null;

    protected function setUp(): void
    {
        $config = [
            'engine' => 'pdo',
            'driver' => 'mysql',
            'host' => getenv('DB_HOST') ?: 'localhost',
            'port' => (int) (getenv('DB_PORT') ?: 3306),
            'database' => getenv('DB_NAME') ?: 'versaorm_test',
            'username' => getenv('DB_USER') ?: 'local',
            'password' => getenv('DB_PASS') ?: 'local',
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

    public function test_commit_persists_changes(): void
    {
        $this->orm->beginTransaction();
        $this->orm->table('tx_users')->insert(['name' => 'Tx Commit', 'email' => 'tx.commit@example.com']);
        $this->orm->commit();

        $found = $this->orm
            ->table('tx_users')
            ->where('email', '=', 'tx.commit@example.com')
            ->findOne();
        static::assertNotNull($found);
        static::assertSame('Tx Commit', $found->name);
    }

    public function test_rollback_reverts_changes(): void
    {
        // Estado inicial vacío
        $pre = $this->orm
            ->table('tx_users')
            ->where('email', '=', 'tx.rollback@example.com')
            ->findOne();
        static::assertNull($pre);

        // Iniciar transacción y generar un cambio
        $this->orm->beginTransaction();
        $this->orm->table('tx_users')->insert(['name' => 'Tx Rollback', 'email' => 'tx.rollback@example.com']);

        // Verificar que el cambio se ve dentro de la transacción (si el aislamiento lo permite)
        $mid = $this->orm
            ->table('tx_users')
            ->where('email', '=', 'tx.rollback@example.com')
            ->findOne();
        static::assertNotNull($mid);

        // Revertir
        $this->orm->rollBack();

        // Debe no existir al final
        $post = $this->orm
            ->table('tx_users')
            ->where('email', '=', 'tx.rollback@example.com')
            ->findOne();
        static::assertNull($post);
    }
}
