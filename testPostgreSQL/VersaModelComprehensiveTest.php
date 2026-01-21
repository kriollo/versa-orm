<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use DateTime;
use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Tests comprehensivos para VersaModel en PostgreSQL
 * Target: 70.67% → 85%+
 */
class VersaModelComprehensiveTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'postgresql',
            'host' => getenv('DB_HOST_PGSQL') ?: 'localhost',
            'port' => (int) (getenv('DB_PORT_PGSQL') ?: 5432),
            'database' => getenv('DB_NAME_PGSQL') ?: 'versaorm_test',
            'username' => getenv('DB_USER_PGSQL') ?: 'local',
            'password' => getenv('DB_PASS_PGSQL') ?: 'local',
            'charset' => 'utf8',
            'debug' => false,
        ]);

        VersaModel::setORM($this->orm);

        // Limpiar tablas existentes
        $this->orm->exec('DROP TABLE IF EXISTS posts CASCADE');
        $this->orm->exec('DROP TABLE IF EXISTS test_models CASCADE');
        $this->orm->exec('DROP TABLE IF EXISTS users_fillable CASCADE');

        // Crear tabla de prueba
        $this->orm->exec('
            CREATE TABLE test_models (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE,
                age INTEGER,
                score REAL,
                active BOOLEAN DEFAULT TRUE,
                metadata TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        ');

        $this->orm->exec('
            CREATE TABLE posts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                title VARCHAR(255),
                content TEXT,
                created_at TIMESTAMP
            )
        ');

        $this->orm->exec('
            CREATE TABLE users_fillable (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255),
                email VARCHAR(255),
                password VARCHAR(255),
                role VARCHAR(50)
            )
        ');
    }

    protected function tearDown(): void
    {
        $this->orm->exec('DROP TABLE IF EXISTS posts CASCADE');
        $this->orm->exec('DROP TABLE IF EXISTS test_models CASCADE');
        $this->orm->exec('DROP TABLE IF EXISTS users_fillable CASCADE');

        // PostgreSQL no requiere close() explícito
    }

    /** Test: __construct con diferentes configuraciones */
    public function testConstructorWithArrayConfig(): void
    {
        $config = [
            'driver' => 'postgresql',
            'database' => 'test',
        ];

        $model = new VersaModel('test_models', $config);
        static::assertEquals('test_models', $model->getTable());
    }

    /** Test: __set y __get básicos */
    public function testMagicSetAndGet(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'John Doe';
        $model->age = 30;

        static::assertEquals('John Doe', $model->name);
        static::assertEquals(30, $model->age);
    }

    /** Test: __isset y __unset */
    public function testMagicIssetAndUnset(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Test';

        static::assertTrue(isset($model->name));

        unset($model->name);

        static::assertFalse(isset($model->name));
    }

    /** Test: __get con orm/db shortcuts */
    public function testMagicGetOrmShortcuts(): void
    {
        $model = VersaModel::dispense('test_models');
        static::assertInstanceOf(VersaORM::class, $model->orm);
        static::assertInstanceOf(VersaORM::class, $model->db);
    }

    /** Test: fill con fillable */
    public function testFillWithFillableArray(): void
    {
        $model = new class('users_fillable', VersaModel::orm()) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $model->fill([
            'name' => 'John',
            'email' => 'john@example.com',
            'password' => 'secret',
        ]);

        static::assertEquals('John', $model->name);
        static::assertEquals('john@example.com', $model->email);
        static::assertNull($model->password);
    }

    /** Test: fill con guarded */
    public function testFillWithGuardedArray(): void
    {
        $model = new class('users_fillable', VersaModel::orm()) extends VersaModel {
            protected array $fillable = [];
            protected array $guarded = ['password'];
        };

        $model->fill([
            'name' => 'Jane',
            'email' => 'jane@example.com',
            'password' => 'secret',
        ]);

        static::assertEquals('Jane', $model->name);
        static::assertNull($model->password);
    }

    /** Test: store inserta y actualiza */
    public function testStoreInsertsAndUpdates(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'New User';
        $model->email = 'newuser@example.com';

        $id = $model->store();
        static::assertGreaterThan(0, $id);

        // Actualizar
        $model->name = 'Updated User';
        $model->store();

        $record = $this->orm
            ->table('test_models')
            ->where('id', '=', $id)
            ->first();
        static::assertEquals('Updated User', $record['name']);
    }

    /** Test: trash elimina */
    public function testTrashDeletesRecord(): void
    {
        $id = $this->orm
            ->table('test_models')
            ->insertGetId([
                'name' => 'To Delete',
                'email' => 'delete@example.com',
            ]);

        $model = VersaModel::dispense('test_models');
        $model->id = $id;
        $model->trash();

        $count = $this->orm
            ->table('test_models')
            ->where('id', '=', $id)
            ->count();
        static::assertEquals(0, $count);
    }

    /** Test: fresh recarga desde BD */
    public function testFreshReloadsFromDatabase(): void
    {
        $id = $this->orm
            ->table('test_models')
            ->insertGetId([
                'name' => 'Original Name',
                'email' => 'original@example.com',
            ]);

        $model = VersaModel::dispense('test_models');
        $model->id = $id;
        $model->name = 'Modified';

        $freshModel = $model->fresh();
        static::assertEquals('Original Name', $freshModel->name);
    }

    /** Test: upsert con unique keys */
    public function testUpsertWithUniqueKeys(): void
    {
        $model1 = VersaModel::dispense('test_models');
        $model1->email = 'unique@example.com';
        $model1->name = 'First';
        $result1 = $model1->upsert(['email'], ['name']);

        static::assertEquals('inserted', $result1['action']);

        $model2 = VersaModel::dispense('test_models');
        $model2->email = 'unique@example.com';
        $model2->name = 'Updated';
        $result2 = $model2->upsert(['email'], ['name']);

        static::assertEquals('updated', $result2['action']);
    }

    /** Test: castToPhpType con diferentes tipos */
    public function testCastToPhpTypeWithVariousTypes(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            public static function getPropertyTypes(): array
            {
                return [
                    'age' => ['type' => 'integer'],
                    'score' => ['type' => 'float'],
                    'active' => ['type' => 'boolean'],
                    'metadata' => ['type' => 'json'],
                    'created_at' => ['type' => 'datetime'],
                ];
            }
        };

        // Integer
        static::assertSame(30, $model->castToPhpType('age', '30'));

        // Float
        static::assertSame(95.5, $model->castToPhpType('score', '95.5'));

        // Boolean
        static::assertTrue($model->castToPhpType('active', 't')); // PostgreSQL format
        static::assertFalse($model->castToPhpType('active', 'f')); // PostgreSQL format

        // JSON
        $json = '{"key":"value"}';
        $result = $model->castToPhpType('metadata', $json);
        static::assertIsArray($result);
        static::assertEquals('value', $result['key']);

        // Datetime
        $dt = $model->castToPhpType('created_at', '2025-01-21 10:30:00');
        static::assertInstanceOf(DateTime::class, $dt);
    }

    /** Test: Lazy casting cache */
    public function testLazyCastingCachesValues(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            public static function getPropertyTypes(): array
            {
                return [
                    'age' => ['type' => 'integer'],
                ];
            }
        };

        $model->age = '42';

        // Primer acceso castea
        $first = $model->age;
        static::assertSame(42, $first);

        // Segundo acceso usa cache
        $second = $model->age;
        static::assertSame(42, $second);
        static::assertSame($first, $second);
    }

    /** Test: getUniqueKeys detecta índices únicos */
    public function testGetUniqueKeysDetectsIndexes(): void
    {
        $model = VersaModel::dispense('test_models');
        $uniqueKeys = $model->getUniqueKeys();

        static::assertIsArray($uniqueKeys);
        static::assertContains('email', $uniqueKeys);
    }

    /** Test: smartUpsert usa claves únicas */
    public function testSmartUpsertUsesUniqueKeys(): void
    {
        $model1 = VersaModel::dispense('test_models');
        $model1->email = 'smart@example.com';
        $model1->name = 'Smart User';
        $result1 = $model1->smartUpsert();

        static::assertEquals('inserted', $result1['action']);

        $model2 = VersaModel::dispense('test_models');
        $model2->email = 'smart@example.com';
        $model2->name = 'Updated Smart';
        $result2 = $model2->smartUpsert();

        static::assertEquals('updated', $result2['action']);
    }

    /** Test: save auto-detecta insert/update */
    public function testSaveAutoDetectsOperation(): void
    {
        // Sin ID = INSERT
        $model1 = VersaModel::dispense('test_models');
        $model1->name = 'New';
        $model1->email = 'new@example.com';
        $result1 = $model1->save();

        static::assertEquals('inserted', $result1['action']);

        // Con ID = UPDATE
        $model2 = VersaModel::dispense('test_models');
        $model2->id = $result1['id'];
        $model2->name = 'Updated';
        $result2 = $model2->save();

        static::assertEquals('updated', $result2['action']);
    }

    /** Test: loadInstance con datos completos */
    public function testLoadInstanceWithCompleteData(): void
    {
        $data = [
            'id' => 1,
            'name' => 'Alice',
            'email' => 'alice@example.com',
            'age' => 25,
        ];

        $model = VersaModel::dispense('test_models');
        $loaded = $model->loadInstance($data);

        static::assertEquals(1, $loaded->id);
        static::assertEquals('Alice', $loaded->name);
        static::assertEquals(25, $loaded->age);
    }

    /** Test: query methods */
    public function testQueryMethods(): void
    {
        $model = VersaModel::dispense('test_models');

        $query1 = $model->newQuery();
        static::assertInstanceOf(\VersaORM\QueryBuilder::class, $query1);

        $query2 = $model->query();
        static::assertInstanceOf(\VersaORM\QueryBuilder::class, $query2);

        $query3 = $model->query('custom_table');
        static::assertInstanceOf(\VersaORM\QueryBuilder::class, $query3);
    }

    /** Test: getData y getDataCasted */
    public function testGetDataMethods(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Test';
        $model->age = 30;

        $rawData = $model->getData();
        static::assertIsArray($rawData);
        static::assertArrayHasKey('name', $rawData);

        $castedData = $model->getDataCasted();
        static::assertIsArray($castedData);
    }

    /** Test: export incluye relaciones */
    public function testExportIncludesRelations(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->id = 1;
        $model->relations = [
            'posts' => [['id' => 1, 'title' => 'Post 1']],
        ];

        $exported = $model->export();
        static::assertArrayHasKey('posts', $exported);
    }

    /** Test: getAttribute */
    public function testGetAttribute(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Test';

        static::assertEquals('Test', $model->getAttribute('name'));
        static::assertNull($model->getAttribute('nonExistent'));
    }

    /** Test: update modifica atributos */
    public function testUpdateModifiesAttributes(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Original';
        $model->email = 'original@example.com';

        $model->update(['name' => 'Updated']);

        static::assertEquals('Updated', $model->name);
        static::assertEquals('original@example.com', $model->email);
    }

    /** Test: getForeignKey */
    public function testGetForeignKey(): void
    {
        $model = VersaModel::dispense('test_models');
        static::assertEquals('test_models_id', $model->getForeignKey());
    }

    /** Test: getKeyName */
    public function testGetKeyName(): void
    {
        $model = VersaModel::dispense('test_models');
        static::assertEquals('id', $model->getKeyName());
    }

    /** Test: storeAndGetId */
    public function testStoreAndGetId(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Test';
        $model->email = 'test@example.com';

        $id = $model->storeAndGetId();
        static::assertGreaterThan(0, $id);
    }

    /** Test: convertValueByTypeMapping */
    public function testConvertValueByTypeMapping(): void
    {
        $model = VersaModel::dispense('test_models');

        $schema = ['type' => 'boolean'];
        static::assertTrue($model->convertValueByTypeMapping('active', true, $schema));

        $schema = ['type' => 'integer'];
        static::assertSame(42, $model->convertValueByTypeMapping('age', '42', $schema));
    }

    /** Test: isFillable y isGuarded */
    public function testIsFillableAndIsGuarded(): void
    {
        $model = new class('users_fillable', VersaModel::orm()) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        static::assertTrue($model->isFillable('name'));
        static::assertFalse($model->isFillable('password'));
    }

    /** Test: getFillable y getGuarded */
    public function testGetFillableAndGuarded(): void
    {
        $model = new class('users_fillable', VersaModel::orm()) extends VersaModel {
            protected array $fillable = ['name', 'email'];
            protected array $guarded = ['password'];
        };

        static::assertContains('name', $model->getFillable());
        static::assertContains('password', $model->getGuarded());
    }

    /** Test: dispenseInstance */
    public function testDispenseInstance(): void
    {
        $model = VersaModel::dispense('test_models');
        $newInstance = $model->dispenseInstance('posts');

        static::assertInstanceOf(VersaModel::class, $newInstance);
        static::assertEquals('posts', $newInstance->getTable());
    }

    /** Test: getOrm */
    public function testGetOrm(): void
    {
        $model = VersaModel::dispense('test_models');
        static::assertInstanceOf(VersaORM::class, $model->getOrm());
    }

    /** Test: insertOrUpdate */
    public function testInsertOrUpdate(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->email = 'insertorupdate@example.com';
        $model->name = 'Test';

        $result = $model->insertOrUpdate(['email'], ['name']);
        static::assertArrayHasKey('action', $result);
    }

    /** Test: createOrUpdate */
    public function testCreateOrUpdate(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Test';
        $model->email = 'createorupdate@example.com';

        $result = $model->createOrUpdate(['email' => 'createorupdate@example.com'], ['name']);

        static::assertArrayHasKey('action', $result);
    }
}
