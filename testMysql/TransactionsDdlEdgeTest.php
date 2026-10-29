<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

/**
 * Casos borde del commit implícito del DDL en MySQL/MariaDB: el arreglo de 2.2.3 no debe ocultar
 * errores de programación (commit sin transacción) ni dejar el estado transaccional corrupto.
 *
 * @group mysql
 */
class TransactionsDdlEdgeTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'engine' => 'pdo',
            'driver' => 'mysql',
            'host' => getenv('DB_HOST') ?: 'localhost',
            'port' => (int) (getenv('DB_PORT') ?: 3306),
            'database' => getenv('DB_NAME') ?: 'versaorm_test',
            'username' => getenv('DB_USER') ?: 'local',
            'password' => getenv('DB_PASS') ?: 'local',
        ]);
        $this->orm->exec('DROP TABLE IF EXISTS tx_borde, tx_borde_ddl');
        $this->orm->exec('CREATE TABLE tx_borde (id INT PRIMARY KEY, nombre VARCHAR(50))');
    }

    protected function tearDown(): void
    {
        $this->orm->exec('DROP TABLE IF EXISTS tx_borde, tx_borde_ddl');
    }

    public function test_commit_sin_transaccion_sigue_siendo_un_error(): void
    {
        // Sin DDL de por medio no hay commit implícito que justifique callar: es un error del llamador
        $this->expectException(VersaORMException::class);
        $this->orm->commit();
    }

    public function test_rollback_sin_transaccion_sigue_siendo_un_error(): void
    {
        $this->expectException(VersaORMException::class);
        $this->orm->rollBack();
    }

    public function test_un_segundo_commit_tras_ddl_es_un_error(): void
    {
        $this->orm->beginTransaction();
        $this->orm->exec('CREATE TABLE tx_borde_ddl (id INT)');
        $this->orm->commit();

        // El primero cerró el estado transaccional: el segundo ya no tiene nada que confirmar
        $this->expectException(VersaORMException::class);
        $this->orm->commit();
    }

    public function test_tras_el_commit_implicito_una_transaccion_nueva_revierte_normalmente(): void
    {
        $this->orm->beginTransaction();
        $this->orm->exec('CREATE TABLE tx_borde_ddl (id INT)');
        $this->orm->rollBack();

        $this->orm->beginTransaction();
        $this->orm->exec("INSERT INTO tx_borde (id, nombre) VALUES (1, 'revertida')");
        $this->orm->rollBack();

        static::assertNull($this->orm->table('tx_borde')->where('id', '=', 1)->findOne());
    }

    public function test_los_datos_escritos_antes_del_ddl_quedan_confirmados_aunque_se_haga_rollback(): void
    {
        // Limitación de MySQL/MariaDB, documentada: el DDL confirma lo anterior y rollBack() ya no lo revierte
        $this->orm->beginTransaction();
        $this->orm->exec("INSERT INTO tx_borde (id, nombre) VALUES (2, 'antes del ddl')");
        $this->orm->exec('CREATE TABLE tx_borde_ddl (id INT)');
        $this->orm->rollBack();

        static::assertNotNull($this->orm->table('tx_borde')->where('id', '=', 2)->findOne());
    }

    public function test_el_esquema_cacheado_ve_la_columna_agregada_dentro_de_la_transaccion(): void
    {
        static::assertNotContains('extra', array_column($this->orm->schema('columns', 'tx_borde'), 'name'));

        $this->orm->beginTransaction();
        $this->orm->exec('ALTER TABLE tx_borde ADD COLUMN extra VARCHAR(10) NULL');
        $this->orm->commit();

        static::assertContains('extra', array_column($this->orm->schema('columns', 'tx_borde'), 'name'));
    }
}
