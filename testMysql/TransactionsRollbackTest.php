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

        $found = $this->orm->table('tx_users')->where('email', '=', 'tx.commit@example.com')->findOne();
        static::assertNotNull($found);
        static::assertSame('Tx Commit', $found->name);
    }

    public function test_rollback_reverts_changes(): void
    {
        // Estado inicial vacío
        $pre = $this->orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        static::assertNull($pre);

        // Iniciar transacción y generar un cambio
        $this->orm->beginTransaction();
        $this->orm->table('tx_users')->insert(['name' => 'Tx Rollback', 'email' => 'tx.rollback@example.com']);

        // Verificar que el cambio se ve dentro de la transacción (si el aislamiento lo permite)
        $mid = $this->orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        static::assertNotNull($mid);

        // Revertir
        $this->orm->rollBack();

        // Debe no existir al final
        $post = $this->orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        static::assertNull($post);
    }

    /**
     * MySQL/MariaDB: el DDL dentro de una transacción lo confirma implícitamente y el
     * driver PDO detecta el autocommit (inTransaction() pasa a false). Al ejecutar
     * COMMIT el motor no debe lanzar "There is no active transaction".
     */
    public function test_commit_after_ddl_in_transaction_does_not_throw(): void
    {
        $this->orm->exec('DROP TABLE IF EXISTS tx_ddl_commit');

        $this->orm->beginTransaction();
        $this->orm->exec('CREATE TABLE tx_ddl_commit (id INT PRIMARY KEY, nombre VARCHAR(50))');
        $this->orm->exec("INSERT INTO tx_ddl_commit (id, nombre) VALUES (1, 'auto')");

        // No debe lanzar excepción
        $this->orm->commit();

        // El dato quedó persistido (el autocommit del DDL confirmó la transacción)
        $row = $this->orm->table('tx_ddl_commit')->findOne();
        static::assertNotNull($row);
        static::assertSame('auto', $row->nombre);

        $this->orm->exec('DROP TABLE IF EXISTS tx_ddl_commit');
    }

    /**
     * Igual que el anterior, pero con rollback: el motor debe ser un no-op seguro
     * (en MySQL/MariaDB el DDL ya quedó confirmado por el autocommit).
     */
    public function test_rollback_after_ddl_in_transaction_does_not_throw(): void
    {
        $this->orm->exec('DROP TABLE IF EXISTS tx_ddl_rollback');

        $this->orm->beginTransaction();
        $this->orm->exec('CREATE TABLE tx_ddl_rollback (id INT PRIMARY KEY)');

        // No debe lanzar excepción
        $this->orm->rollBack();

        // Limitación del autocommit de DDL en MySQL/MariaDB: la tabla sigue existiendo
        // y es usable. En PostgreSQL/SQLite el rollback sí eliminaría el CREATE.
        $this->orm->exec('INSERT INTO tx_ddl_rollback (id) VALUES (2)');
        $this->orm->exec('DROP TABLE IF EXISTS tx_ddl_rollback');

        static::assertTrue(true);
    }
}
