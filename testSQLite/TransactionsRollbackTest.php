<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaORMException;

/**
 * Pruebas de transacciones (commit / rollback) sobre SQLite usando la API del ORM.
 */
class TransactionsRollbackTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Crear tabla de pruebas aislada para transacciones
        self::$orm->exec('DROP TABLE IF EXISTS tx_users');
        self::$orm->schemaCreate(
            'tx_users',
            [
                ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(100)', 'nullable' => false],
                ['name' => 'email', 'type' => 'VARCHAR(191)', 'nullable' => false],
            ],
            [
                'constraints' => [
                    'unique' => [['name' => 'tx_users_email_unique', 'columns' => ['email']]],
                ],
            ],
        );
    }

    protected function tearDown(): void
    {
        // Limpiar tabla de pruebas de transacciones
        try {
            self::$orm->exec('DROP TABLE IF EXISTS tx_users');
        } catch (VersaORMException $e) {
            // Ignorar errores de limpieza
        }
        parent::tearDown();
    }

    public function test_commit_persists_changes(): void
    {
        self::$orm->beginTransaction();
        self::$orm->table('tx_users')->insert(['name' => 'Tx Commit', 'email' => 'tx.commit@example.com']);
        self::$orm->commit();

        $found = self::$orm->table('tx_users')->where('email', '=', 'tx.commit@example.com')->firstArray();
        static::assertNotNull($found);
        static::assertSame('Tx Commit', $found['name'] ?? null);
    }

    public function test_rollback_reverts_changes(): void
    {
        $pre = self::$orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->firstArray();
        static::assertNull($pre);

        self::$orm->beginTransaction();
        self::$orm->table('tx_users')->insert(['name' => 'Tx Rollback', 'email' => 'tx.rollback@example.com']);

        $mid = self::$orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->firstArray();
        static::assertNotNull($mid);

        self::$orm->rollBack();

        $post = self::$orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->firstArray();
        static::assertNull($post);
    }
}
