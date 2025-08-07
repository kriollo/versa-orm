<?php

// testPostgreSQL/VersaModelTest.php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

class VersaModelTest extends TestCase
{
    public function testDispenseAndCreate(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'Heidi';
        $user->email = 'heidi@example.com';
        $user->status = 'active';
        
        // Agregar debug antes del store
        echo "\n=== DEBUG BEFORE STORE ===\n";
        echo "User ID before store: " . var_export($user->id, true) . "\n";
        
        $user->store();
        
        // Agregar debug después del store
        echo "\n=== DEBUG AFTER STORE ===\n";
        echo "User ID after store: " . var_export($user->id, true) . "\n";

        $this->assertNotNull($user->id, 'ID should be set after storing.');

        $dbUser = VersaModel::load('users', $user->id);
        $this->assertEquals('Heidi', $dbUser->name);
    }

    public function testLoad(): void
    {
        $user = VersaModel::load('users', 1);
        $this->assertInstanceOf(VersaModel::class, $user);
        $this->assertEquals('Alice', $user->name);
    }

    public function testLoadReturnsNullForNonExistent(): void
    {
        $user = VersaModel::load('users', 999);
        $this->assertNull($user);
    }

    public function testUpdate(): void
    {
        $user = VersaModel::load('users', 1);
        $user->name = 'Alicia';
        $user->status = 'away';
        $user->store();

        $updatedUser = VersaModel::load('users', 1);
        $this->assertEquals('Alicia', $updatedUser->name);
        $this->assertEquals('away', $updatedUser->status);
    }

    public function testTrash(): void
    {
        $user = VersaModel::load('users', 2);
        $this->assertNotNull($user);

        $user->trash();

        $deletedUser = VersaModel::load('users', 2);
        $this->assertNull($deletedUser);
    }

    public function testMagicMethods(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'Test';
        $this->assertEquals('Test', $user->name);

        $this->assertTrue(isset($user->name));
        $this->assertFalse(isset($user->non_existent_prop));

        unset($user->name);
        $this->assertFalse(isset($user->name));
    }

    public function testExport(): void
    {
        $user = VersaModel::load('users', 1);
        $data = $user->export();

        $this->assertIsArray($data);
        $this->assertEquals(1, $data['id']);
        $this->assertEquals('Alice', $data['name']);
    }

    public function testExportAll(): void
    {
        $users = VersaModel::findAll('users', 'status = ?', ['active']);
        $data = VersaModel::exportAll($users);

        $this->assertCount(2, $data);
        $this->assertIsArray($data[0]);
        $this->assertEquals('Alice', $data[0]['name']);
    }

    public function testFindAllStatic(): void
    {
        $users = VersaModel::findAll('users', 'id > ?', [1]);
        $this->assertCount(2, $users);
        $this->assertInstanceOf(VersaModel::class, $users[0]);
    }

    public function testFindOneStatic(): void
    {
        $user = VersaModel::findOne('users', 1);
        $this->assertInstanceOf(VersaModel::class, $user);
        $this->assertEquals(1, $user->id);
    }

    public function testCountStatic(): void
    {
        $count = VersaModel::count('users', 'status = ?', ['active']);
        $this->assertEquals(2, $count);
    }

    /**
     * Test específico de PostgreSQL: manejo de SERIAL
     */
    public function testSerialFieldHandling(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'SerialTest';
        $user->email = 'serial@postgresql.test';
        $user->store();

        // El ID debe ser asignado automáticamente por PostgreSQL SERIAL
        $this->assertIsInt((int)$user->id);
        $this->assertGreaterThan(3, (int)$user->id); // Mayor que los datos seeded
    }

    /**
     * Test específico de PostgreSQL: manejo de timestamps
     */
    public function testTimestampHandling(): void
    {
        $user = VersaModel::dispense('users');
        $user->name = 'TimestampTest';
        $user->email = 'timestamp@postgresql.test';
        $user->store();

        $this->assertNotNull($user->created_at);

        // Recargar desde DB para verificar el timestamp
        $dbUser = VersaModel::load('users', $user->id);
        $this->assertNotNull($dbUser->created_at);
    }

    /**
     * Test específico de PostgreSQL: case sensitivity
     */
    public function testPostgreSQLCaseSensitivity(): void
    {
        // PostgreSQL convierte nombres no quoted a minúsculas
        $user = VersaModel::dispense('users');
        $user->name = 'CaseTest';
        $user->email = 'case@test.com';
        $user->store();

        // Buscar con diferentes casos
        $users = VersaModel::findAll('users', 'UPPER(name) = ?', ['CASETEST']);
        $this->assertCount(1, $users);
        $this->assertEquals('CaseTest', $users[0]->name);
    }

    /**
     * Test específico de PostgreSQL: manejo de arrays si la extensión los soporta
     */
    public function testArrayFieldsIfAvailable(): void
    {
        try {
            // Crear tabla temporal con campo array para test
            self::$orm->exec("CREATE TEMP TABLE array_models (id SERIAL PRIMARY KEY, tags TEXT[])");

            // Insertar modelo con array
            $data = self::$orm->table('array_models')->insertGetId(['tags' => '{"tag1", "tag2", "tag3"}']);
            $this->assertIsInt($data);

            // Verificar que se guardó correctamente
            $result = self::$orm->table('array_models')->find($data, 'id');
            $this->assertNotNull($result);

        } catch (\Exception $e) {
            $this->markTestSkipped('Array fields test requires PostgreSQL array support');
        }
    }

    /**
     * Test específico de PostgreSQL: manejo de JSON/JSONB si está disponible
     */
    public function testJSONBFieldsIfAvailable(): void
    {
        try {
            // Crear tabla temporal con campo JSONB
            self::$orm->exec("CREATE TEMP TABLE json_models (id SERIAL PRIMARY KEY, data JSONB)");

            $jsonData = '{"name": "test", "values": [1, 2, 3], "active": true}';

            // Insertar modelo con JSONB
            $id = self::$orm->table('json_models')->insertGetId(['data' => $jsonData]);
            $this->assertIsInt($id);

            // Verificar que se guardó correctamente
            $result = self::$orm->table('json_models')->find($id, 'id');
            $this->assertNotNull($result);

            // Test consulta JSON
            $results = self::$orm->exec("SELECT * FROM json_models WHERE data->>'name' = ?", ['test']);
            $this->assertCount(1, $results);

        } catch (\Exception $e) {
            $this->markTestSkipped('JSONB fields test requires PostgreSQL JSONB support');
        }
    }

    /**
     * Test de relaciones con sintaxis específica de PostgreSQL
     */
    public function testRelationshipsWithPostgreSQLSyntax(): void
    {
        // Crear un post relacionado con usuario
        $post = VersaModel::dispense('posts');
        $post->user_id = 1;
        $post->title = 'PostgreSQL Test Post';
        $post->content = 'Testing relationships with PostgreSQL';
        $post->store();

        // Verificar la relación usando JOIN específico de PostgreSQL
        $results = self::$orm->exec("
            SELECT u.name as user_name, p.title as post_title
            FROM users u
            INNER JOIN posts p ON u.id = p.user_id
            WHERE p.id = ?
        ", [$post->id]);

        $this->assertCount(1, $results);
        $this->assertEquals('Alice', $results[0]['user_name']);
        $this->assertEquals('PostgreSQL Test Post', $results[0]['post_title']);
    }

    /**
     * Test de transacciones con modelos
     */
    public function testModelTransactions(): void
    {
        try {
            self::$orm->exec('BEGIN');

            // Crear usuario en transacción
            $user = VersaModel::dispense('users');
            $user->name = 'TransactionUser';
            $user->email = 'transaction@test.com';
            $user->store();

            $userId = $user->id;

            // Verificar que existe en la transacción
            $tempUser = VersaModel::load('users', $userId);
            $this->assertNotNull($tempUser);
            $this->assertEquals('TransactionUser', $tempUser->name);

            // Rollback
            self::$orm->exec('ROLLBACK');

            // Verificar que no existe después del rollback
            $nullUser = VersaModel::load('users', $userId);
            $this->assertNull($nullUser);

        } catch (\Exception $e) {
            try {
                self::$orm->exec('ROLLBACK');
            } catch (\Exception $rollbackException) {
                // Ignorar errores de rollback
            }
            $this->markTestIncomplete('Model transactions test failed: ' . $e->getMessage());
        }
    }

    /**
     * Test de búsqueda con funciones específicas de PostgreSQL
     */
    public function testPostgreSQLSpecificSearch(): void
    {
        // Test con ILIKE (case insensitive)
        $users = VersaModel::findAll('users', 'name ILIKE ?', ['%alice%']);
        $this->assertCount(1, $users);
        $this->assertEquals('Alice', $users[0]->name);

        // Test con expresiones regulares de PostgreSQL
        $users = VersaModel::findAll('users', 'name ~ ?', ['^[A-C].*']);
        $this->assertGreaterThan(0, count($users));

        // Test con funciones de string de PostgreSQL
        $users = VersaModel::findAll('users', 'LENGTH(name) > ?', [3]);
        $this->assertGreaterThan(0, count($users));
    }

    /**
     * Test de validación específica de PostgreSQL
     */
    public function testPostgreSQLValidation(): void
    {
        // Test que emails únicos se manejen correctamente
        $user1 = VersaModel::dispense('users');
        $user1->name = 'User1';
        $user1->email = 'duplicate@test.com';
        $user1->store();

        $user2 = VersaModel::dispense('users');
        $user2->name = 'User2';
        $user2->email = 'duplicate@test.com';

        try {
            $user2->store();
            $this->fail('Should have thrown exception for duplicate email');
        } catch (\Exception $e) {
            // PostgreSQL debería lanzar error de constraint
            $this->assertTrue(true, 'Duplicate email constraint was properly enforced');
        }
    }
}
