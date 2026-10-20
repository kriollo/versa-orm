<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use Throwable;

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
        } catch (Throwable $e) {
            // ignorar si no existe
        }

        // Crear tabla portable con PK autoincremental y UNIQUE(email)
        self::$orm->schemaCreate(
            'tx_users',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(100)', 'nullable' => false],
                ['name' => 'email', 'type' => 'VARCHAR(191)', 'nullable' => false],
            ],
            [
                'constraints' => [
                    'unique' => [
                        ['name' => 'uniq_tx_users_email', 'columns' => ['email']],
                    ],
                ],
            ],
        );
    }

    protected function tearDown(): void
    {
        try {
            self::$orm->schemaDrop('tx_users');
        } catch (Throwable $e) { // ignore
        }
    }

    public function test_commit_persists_changes(): void
    {
        self::$orm->beginTransaction();
        self::$orm->table('tx_users')->insert(['name' => 'Tx Commit', 'email' => 'tx.commit@example.com']);
        self::$orm->commit();

        $found = self::$orm->table('tx_users')->where('email', '=', 'tx.commit@example.com')->findOne();
        static::assertNotNull($found);
        static::assertSame('Tx Commit', $found->name);
    }

    public function test_rollback_reverts_changes(): void
    {
        // Estado inicial vacío
        $pre = self::$orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        static::assertNull($pre);

        // Iniciar transacción y generar un cambio
        self::$orm->beginTransaction();
        self::$orm->table('tx_users')->insert(['name' => 'Tx Rollback', 'email' => 'tx.rollback@example.com']);

        // Verificar que el cambio se ve dentro de la transacción (si el aislamiento lo permite)
        $mid = self::$orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        static::assertNotNull($mid);

        // Revertir
        self::$orm->rollBack();

        // Debe no existir al final
        $post = self::$orm->table('tx_users')->where('email', '=', 'tx.rollback@example.com')->findOne();
        static::assertNull($post);
    }

    public function test_commit_y_rollback_sin_transaccion_siguen_siendo_un_error(): void
    {
        foreach (['commit', 'rollBack'] as $metodo) {
            try {
                self::$orm->{$metodo}();
                static::fail("{$metodo}() sin transacción debería lanzar");
            } catch (\VersaORM\VersaORMException) {
                static::assertTrue(true);
            }
        }
    }

    public function test_el_ddl_dentro_de_una_transaccion_se_revierte_con_rollback(): void
    {
        // A diferencia de MySQL, aquí el DDL es transaccional: rollBack() deshace el CREATE
        self::$orm->exec('DROP TABLE IF EXISTS tx_ddl_revertido');
        self::$orm->beginTransaction();
        self::$orm->exec('CREATE TABLE tx_ddl_revertido (id INT)');
        self::$orm->rollBack();

        static::assertNotContains('tx_ddl_revertido', self::$orm->schema('tables'));

        // Y el estado transaccional queda limpio: una transacción nueva confirma normalmente
        self::$orm->beginTransaction();
        self::$orm->exec('CREATE TABLE tx_ddl_revertido (id INT)');
        self::$orm->commit();
        static::assertContains('tx_ddl_revertido', self::$orm->schema('tables'));
        self::$orm->exec('DROP TABLE IF EXISTS tx_ddl_revertido');
    }
}
