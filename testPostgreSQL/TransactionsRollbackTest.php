<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

/**
 * Pruebas de transacciones: commit y rollback usando las APIs del ORM/QueryBuilder.
 */
class TransactionsRollbackTest extends TestCase
{
    protected function setUp(): void
    {
        // No llamamos a parent::setUp() para evitar recrear el esquema base; este test usa su propia tabla
        // Asegurar estado limpio e independiente del driver
        try {
            self::$orm->schemaDrop('tx_users');
        } catch (\Throwable $e) {
            // ignorar si no existe
        }

        // Crear tabla portable con PK autoincremental y UNIQUE(email)
        self::$orm->schemaCreate('tx_users', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(100)', 'nullable' => false],
            ['name' => 'email', 'type' => 'VARCHAR(191)', 'nullable' => false],
        ], [
            'constraints' => [
                'unique' => [
                    ['name' => 'uniq_tx_users_email', 'columns' => ['email']]
                ]
            ]
        ]);
    }

    protected function tearDown(): void
    {
        try {
            self::$orm->schemaDrop('tx_users');
        } catch (\Throwable $e) { /* ignore */
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
