<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Test para validar que 'versa_users' es un nombre de tabla válido con alias en PostgreSQL.
 * Verifica que el ORM no rechace nombres de tabla que comienzan con prefijos específicos.
 */
/**
 * @group postgresql
 */
class VersaUsersTableAliasTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'postgresql',
            'host' => getenv('DB_HOST') ?: 'localhost',
            'database' => getenv('DB_NAME') ?: 'versaorm_test',
            'username' => getenv('DB_USER') ?: 'local',
            'password' => getenv('DB_PASS') ?: 'local',
            'port' => (int) (getenv('DB_PORT') ?: 5432),
            'debug' => false,
        ]);

        VersaModel::setORM($this->orm);

        // Limpiar tabla si existe
        try {
            $this->orm->exec('DROP TABLE IF EXISTS versa_users CASCADE');
        } catch (\Exception $e) {
            // Ignorar si la tabla no existe
        }

        // Crear tabla versa_users para las pruebas
        $this->orm->exec('
            CREATE TABLE versa_users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255),
                email VARCHAR(255) UNIQUE,
                active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ');

        // Insertar datos de prueba
        $this->orm->exec('INSERT INTO versa_users (name, email, active) VALUES (?, ?, ?)', [
            'John Doe',
            'john@example.com',
            true,
        ]);
        $this->orm->exec('INSERT INTO versa_users (name, email, active) VALUES (?, ?, ?)', [
            'Jane Smith',
            'jane@example.com',
            true,
        ]);
    }

    protected function tearDown(): void
    {
        try {
            $this->orm->exec('DROP TABLE IF EXISTS versa_users CASCADE');
        } catch (\Exception $e) {
            // Ignorar
        }
    }

    /**
     * Prueba que 'versa_users' es un nombre de tabla válido.
     */
    public function testVersaUsersTableNameIsValid(): void
    {
        $results = $this->orm->table('versa_users')->get();

        static::assertIsArray($results);
        static::assertCount(2, $results);
        static::assertSame('John Doe', $results[0]['name'] ?? null);
    }

    /**
     * Prueba que 'versa_users' funciona con alias corto.
     */
    public function testVersaUsersTableWithSimpleAlias(): void
    {
        $results = $this->orm
            ->table('versa_users as u')
            ->select(['u.id', 'u.name', 'u.email'])
            ->get();

        static::assertIsArray($results);
        static::assertCount(2, $results);
    }

    /**
     * Prueba que 'versa_users' funciona con alias descriptivo.
     */
    public function testVersaUsersTableWithDescriptiveAlias(): void
    {
        $results = $this->orm
            ->table('versa_users as users')
            ->where('users.active', '=', true)
            ->get();

        static::assertIsArray($results);
        static::assertCount(2, $results);
    }

    /**
     * Prueba que 'versa_users' funciona en búsquedas con WHERE.
     */
    public function testVersaUsersTableWithWhereClause(): void
    {
        $results = $this->orm
            ->table('versa_users')
            ->where('email', '=', 'john@example.com')
            ->get();

        static::assertIsArray($results);
        static::assertCount(1, $results);
        static::assertSame('John Doe', $results[0]['name'] ?? null);
    }

    /**
     * Prueba que 'versa_users' funciona en búsquedas con alias en WHERE.
     */
    public function testVersaUsersTableWithAliasInWhere(): void
    {
        $results = $this->orm
            ->table('versa_users as u')
            ->where('u.name', '=', 'Jane Smith')
            ->get();

        static::assertIsArray($results);
        static::assertCount(1, $results);
        static::assertSame('jane@example.com', $results[0]['email'] ?? null);
    }

    /**
     * Prueba que 'versa_users' funciona en conteos.
     */
    public function testVersaUsersTableCount(): void
    {
        $count = $this->orm->table('versa_users as u')->count();

        static::assertSame(2, $count);
    }

    /**
     * Prueba que 'versa_users' funciona con ordenamiento.
     */
    public function testVersaUsersTableWithOrderBy(): void
    {
        $results = $this->orm
            ->table('versa_users as u')
            ->orderBy('u.name', 'ASC')
            ->get();

        static::assertIsArray($results);
        static::assertCount(2, $results);
        static::assertSame('Jane Smith', $results[0]['name'] ?? null);
        static::assertSame('John Doe', $results[1]['name'] ?? null);
    }

    /**
     * Prueba que 'versa_users' funciona en inserciones.
     */
    public function testVersaUsersTableInsert(): void
    {
        $id = $this->orm
            ->table('versa_users')
            ->insertGetId([
                'name' => 'Bob Wilson',
                'email' => 'bob@example.com',
                'active' => true,
            ]);

        static::assertIsInt($id);
        static::assertGreaterThan(0, $id);

        $results = $this->orm->table('versa_users')->count();
        static::assertSame(3, $results);
    }

    /**
     * Prueba que 'versa_users' funciona en actualizaciones con alias.
     */
    public function testVersaUsersTableUpdateWithAlias(): void
    {
        $updated = $this->orm
            ->table('versa_users as u')
            ->where('u.email', '=', 'john@example.com')
            ->update(['name' => 'John Updated']);

        // update() now returns int (affected rows count)
        static::assertIsInt($updated);

        $result = $this->orm
            ->table('versa_users')
            ->where('email', '=', 'john@example.com')
            ->findOne();

        static::assertSame('John Updated', $result->name ?? null);
    }
}
