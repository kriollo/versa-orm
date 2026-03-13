<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use DateTime;
use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Tests comprehensivos para VersaModel para mejorar cobertura
 * Target: 70.67% → 85%+
 */
class VersaModelComprehensiveTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]);

        VersaModel::setORM($this->orm);

        // Crear tabla de prueba con múltiples tipos de datos
        $this->orm->exec('
            CREATE TABLE test_models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE,
                age INTEGER,
                score REAL,
                active BOOLEAN DEFAULT 1,
                metadata TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        ');

        // Tabla para pruebas de relaciones
        $this->orm->exec('
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                content TEXT,
                created_at TEXT
            )
        ');

        // Tabla para pruebas fillable/guarded
        $this->orm->exec('
            CREATE TABLE users_fillable (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT,
                password TEXT,
                role TEXT
            )
        ');
    }

    protected function tearDown(): void
    {
        // No es necesario cerrar la conexión en SQLite :memory:
        // se cierra automáticamente al terminar el script
    }

    /** Test: __construct con diferentes configuraciones */
    public function testConstructorWithArrayConfig(): void
    {
        $config = [
            'driver' => 'sqlite',
            'database' => ':memory:',
        ];

        $model = new VersaModel('test_models', $config);
        static::assertSame('test_models', $model->getTable());
    }

    /** Test: __set y __get básicos */
    public function testMagicSetAndGet(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'John Doe';
        $model->age = 30;

        static::assertSame('John Doe', $model->name);
        static::assertSame(30, $model->age);
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

    /** Test: __get con atributo no existente retorna null */
    public function testMagicGetNonExistentReturnsNull(): void
    {
        $model = VersaModel::dispense('test_models');
        static::assertNull($model->nonExistent);
    }

    /** Test: __get acceso a orm */
    public function testMagicGetOrmShortcut(): void
    {
        $model = VersaModel::dispense('test_models');
        static::assertInstanceOf(VersaORM::class, $model->orm);
        static::assertInstanceOf(VersaORM::class, $model->db);
    }

    /** Test: loadInstance con datos completos */
    public function testLoadInstanceWithCompleteData(): void
    {
        $data = [
            'id' => 1,
            'name' => 'Alice',
            'email' => 'alice@example.com',
            'age' => 25,
            'active' => true,
        ];

        $model = VersaModel::dispense('test_models');
        $loaded = $model->loadInstance($data);

        static::assertSame(1, $loaded->id);
        static::assertSame('Alice', $loaded->name);
        static::assertSame('alice@example.com', $loaded->email);
        static::assertSame(25, $loaded->age);
    }

    /** Test: loadInstance con primary key personalizada */
    public function testLoadInstanceWithCustomPrimaryKey(): void
    {
        $data = [
            'user_id' => 99,
            'name' => 'Custom',
        ];

        $model = VersaModel::dispense('test_models');
        $loaded = $model->loadInstance($data, 'user_id');

        static::assertSame(99, $loaded->user_id);
    }

    /** Test: fill con fillable definido */
    public function testFillWithFillableArray(): void
    {
        $model = new class('users_fillable', VersaModel::orm()) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $model->fill([
            'name' => 'John',
            'email' => 'john@example.com',
        ]);

        static::assertSame('John', $model->name);
        static::assertSame('john@example.com', $model->email);
    }

    /** Test: fill con guarded definido */
    public function testFillWithGuardedArray(): void
    {
        $model = new class('users_fillable', VersaModel::orm()) extends VersaModel {
            protected array $fillable = [];
            protected array $guarded = ['password'];
        };

        $model->fill([
            'name' => 'Jane',
            'email' => 'jane@example.com',
        ]);

        static::assertSame('Jane', $model->name);
        static::assertSame('jane@example.com', $model->email);
    }

    /** Test: isFillable y isGuarded */
    public function testIsFillableAndIsGuarded(): void
    {
        $model = new class('users_fillable', VersaModel::orm()) extends VersaModel {
            protected array $fillable = ['name', 'email'];
            protected array $guarded = [];
        };

        static::assertTrue($model->isFillable('name'));
        static::assertTrue($model->isFillable('email'));
        static::assertFalse($model->isFillable('password'));
    }

    /** Test: update modifica atributos existentes */
    public function testUpdateModifiesAttributes(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $model->name = 'Original';
        $model->email = 'original@example.com';

        $model->update([
            'name' => 'Updated',
        ]);

        static::assertSame('Updated', $model->name);
        static::assertSame('original@example.com', $model->email); // No cambió
    }

    /** Test: getAttribute retorna valor correcto */
    public function testGetAttribute(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Test';

        static::assertSame('Test', $model->getAttribute('name'));
        static::assertNull($model->getAttribute('nonExistent'));
    }

    /** Test: getForeignKey genera nombre correcto */
    public function testGetForeignKey(): void
    {
        $model = VersaModel::dispense('test_models');
        static::assertSame('test_models_id', $model->getForeignKey());
    }

    /** Test: getKeyName retorna 'id' por defecto */
    public function testGetKeyName(): void
    {
        $model = VersaModel::dispense('test_models');
        static::assertSame('id', $model->getKeyName());
    }

    /** Test: newQuery retorna QueryBuilder */
    public function testNewQuery(): void
    {
        $model = VersaModel::dispense('test_models');
        $query = $model->newQuery();

        static::assertInstanceOf(\VersaORM\QueryBuilder::class, $query);
    }

    /** Test: query sin tabla usa getTable() */
    public function testQueryWithoutTableUsesGetTable(): void
    {
        $model = VersaModel::dispense('test_models');
        $query = $model->query();

        static::assertInstanceOf(\VersaORM\QueryBuilder::class, $query);
    }

    /** Test: query con tabla personalizada */
    public function testQueryWithCustomTable(): void
    {
        $model = VersaModel::dispense('test_models');
        $query = $model->query('custom_table');

        static::assertInstanceOf(\VersaORM\QueryBuilder::class, $query);
    }

    /** Test: getData retorna array sin casting */
    public function testGetDataReturnsRawArray(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Test';
        $model->age = 30;

        $data = $model->getData();

        static::assertIsArray($data);
        static::assertArrayHasKey('name', $data);
        static::assertArrayHasKey('age', $data);
    }

    /** Test: getDataCasted retorna array con casting */
    public function testGetDataCastedReturnsProcessedArray(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Test';
        $model->age = '30'; // String que debe castearse a int

        $data = $model->getDataCasted();

        static::assertIsArray($data);
        static::assertArrayHasKey('name', $data);
    }

    /** Test: export incluye relaciones cargadas */
    public function testExportIncludesLoadedRelations(): void
    {
        // Insertar datos de prueba
        $this->orm
            ->table('test_models')
            ->insert([
                'name' => 'User 1',
                'email' => 'user1@example.com',
            ]);

        $this->orm
            ->table('posts')
            ->insert([
                'user_id' => 1,
                'title' => 'Post 1',
                'content' => 'Content 1',
            ]);

        $model = VersaModel::dispense('test_models');
        $model->id = 1;

        // Simular relación cargada usando setRelation
        $model->setRelation('posts', [
            ['id' => 1, 'title' => 'Post 1'],
        ]);

        $exported = $model->export();

        static::assertArrayHasKey('posts', $exported);
    }

    /** Test: getOrm retorna instancia correcta */
    public function testGetOrmReturnsInstance(): void
    {
        $model = VersaModel::dispense('test_models');
        $orm = $model->getOrm();

        static::assertInstanceOf(VersaORM::class, $orm);
    }

    /** Test: fresh recarga modelo desde BD */
    public function testFreshReloadsFromDatabase(): void
    {
        // Insertar registro
        $id = $this->orm
            ->table('test_models')
            ->insertGetId([
                'name' => 'Original Name',
                'email' => 'original@example.com',
            ]);

        $model = VersaModel::dispense('test_models');
        $model->id = $id;
        $model->name = 'Modified Name'; // Modificar localmente

        // Fresh debe recargar desde BD
        $freshModel = $model->fresh();

        static::assertSame('Original Name', $freshModel->name);
    }

    /** Test: trash elimina registro */
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
        static::assertSame(0, $count);
    }

    /** Test: store inserta nuevo registro */
    public function testStoreInsertsNewRecord(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'New User';
        $model->email = 'newuser@example.com';

        $id = $model->store();

        static::assertNotNull($id);
        static::assertGreaterThan(0, $id);

        // Verificar en BD
        $record = $this->orm
            ->table('test_models')
            ->where('id', '=', $id)
            ->firstArray();
        static::assertSame('New User', $record['name']);
    }

    /** Test: store actualiza registro existente */
    public function testStoreUpdatesExistingRecord(): void
    {
        $id = $this->orm
            ->table('test_models')
            ->insertGetId([
                'name' => 'Original',
                'email' => 'original@example.com',
            ]);

        $model = VersaModel::dispense('test_models');
        $model->id = $id;
        $model->name = 'Updated';

        $model->store();

        // Verificar actualización
        $record = $this->orm
            ->table('test_models')
            ->where('id', '=', $id)
            ->firstArray();
        static::assertSame('Updated', $record['name']);
    }

    /** Test: storeAndGetId retorna ID después de insertar */
    public function testStoreAndGetIdReturnsId(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Test User';
        $model->email = 'test@example.com';

        $id = $model->storeAndGetId();

        static::assertNotNull($id);
        static::assertIsInt($id);
        static::assertGreaterThan(0, $id);
    }

    /** Test: validate con reglas personalizadas */
    public function testValidateWithCustomRules(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            protected array $rules = [
                'name' => ['required', 'min:3'],
                'email' => ['required', 'email'],
            ];
        };

        $model->name = 'AB'; // Menos de 3 caracteres
        $model->email = 'invalid-email';

        $errors = $model->validate();

        static::assertNotEmpty($errors);
    }

    /** Test: tableName con clase anónima */
    public function testTableNameInference(): void
    {
        $tableName = VersaModel::tableName();
        static::assertSame('versa_models', $tableName);
    }

    /** Test: dispenseInstance crea nueva instancia */
    public function testDispenseInstanceCreatesNewInstance(): void
    {
        $model = VersaModel::dispense('test_models');
        $newInstance = $model->dispenseInstance('posts');

        static::assertInstanceOf(VersaModel::class, $newInstance);
        static::assertSame('posts', $newInstance->getTable());
    }

    /** Test: castToPhpType con JSON */
    public function testCastToPhpTypeWithJson(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            public static function getPropertyTypes(): array
            {
                return [
                    'metadata' => ['type' => 'json'],
                ];
            }
        };

        $jsonString = '{"key":"value","number":123}';
        $result = $model->castToPhpType('metadata', $jsonString);

        static::assertIsArray($result);
        static::assertSame('value', $result['key']);
        static::assertSame(123, $result['number']);
    }

    /** Test: castToPhpType con datetime */
    public function testCastToPhpTypeWithDatetime(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            public static function getPropertyTypes(): array
            {
                return [
                    'created_at' => ['type' => 'datetime'],
                ];
            }
        };

        $result = $model->castToPhpType('created_at', '2025-01-21 10:30:00');

        static::assertInstanceOf(DateTime::class, $result);
    }

    /** Test: castToPhpType con boolean */
    public function testCastToPhpTypeWithBoolean(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            public static function getPropertyTypes(): array
            {
                return [
                    'active' => ['type' => 'boolean'],
                ];
            }
        };

        static::assertTrue($model->castToPhpType('active', 1));
        static::assertTrue($model->castToPhpType('active', '1'));
        static::assertTrue($model->castToPhpType('active', true));
        static::assertFalse($model->castToPhpType('active', 0));
        static::assertFalse($model->castToPhpType('active', '0'));
        static::assertFalse($model->castToPhpType('active', false));
    }

    /** Test: castToPhpType con integer */
    public function testCastToPhpTypeWithInteger(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            public static function getPropertyTypes(): array
            {
                return [
                    'age' => ['type' => 'integer'],
                ];
            }
        };

        static::assertSame(30, $model->castToPhpType('age', '30'));
        static::assertSame(30, $model->castToPhpType('age', 30.7));
    }

    /** Test: castToPhpType con float */
    public function testCastToPhpTypeWithFloat(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            public static function getPropertyTypes(): array
            {
                return [
                    'score' => ['type' => 'float'],
                ];
            }
        };

        static::assertSame(95.5, $model->castToPhpType('score', '95.5'));
        static::assertSame(95.0, $model->castToPhpType('score', 95));
    }

    /** Test: castToPhpType retorna null si valor es null */
    public function testCastToPhpTypeReturnsNullForNullValue(): void
    {
        $model = VersaModel::dispense('test_models');
        static::assertNull($model->castToPhpType('any_field', null));
    }

    /** Test: Lazy casting - valor se castea solo al acceder */
    public function testLazyCastingOnlyWhenAccessing(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            public static function getPropertyTypes(): array
            {
                return [
                    'age' => ['type' => 'integer'],
                ];
            }
        };

        // Asignar como string
        $model->age = '42';

        // Al acceder, debe castearse a int
        static::assertSame(42, $model->age);
        static::assertIsInt($model->age);
    }

    /** Test: getFillable retorna array correcto */
    public function testGetFillableReturnsArray(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            protected array $fillable = ['name', 'email'];
        };

        $fillable = $model->getFillable();

        static::assertIsArray($fillable);
        static::assertContains('name', $fillable);
        static::assertContains('email', $fillable);
    }

    /** Test: getGuarded retorna array correcto */
    public function testGetGuardedReturnsArray(): void
    {
        $model = new class('test_models', VersaModel::orm()) extends VersaModel {
            protected array $guarded = ['password', 'role'];
        };

        $guarded = $model->getGuarded();

        static::assertIsArray($guarded);
        static::assertContains('password', $guarded);
        static::assertContains('role', $guarded);
    }

    /** Test: upsert con unique keys */
    public function testUpsertWithUniqueKeys(): void
    {
        // Primer insert
        $model1 = VersaModel::dispense('test_models');
        $model1->email = 'unique@example.com';
        $model1->name = 'First';
        $result1 = $model1->upsert(['email'], ['name']);

        static::assertSame('inserted', $result1['action']);

        // Segundo upsert debe actualizar
        $model2 = VersaModel::dispense('test_models');
        $model2->email = 'unique@example.com';
        $model2->name = 'Updated';
        $result2 = $model2->upsert(['email'], ['name']);

        static::assertSame('updated', $result2['action']);

        // Verificar que se actualizó
        $record = $this->orm
            ->table('test_models')
            ->where('email', '=', 'unique@example.com')
            ->firstArray();

        static::assertSame('Updated', $record['name']);
    }

    /** Test: save detecta insert vs update automáticamente */
    public function testSaveAutoDetectsInsertOrUpdate(): void
    {
        // Sin ID = INSERT
        $model1 = VersaModel::dispense('test_models');
        $model1->name = 'New Record';
        $model1->email = 'new@example.com';
        $result1 = $model1->save();

        static::assertSame('inserted', $result1['action']);

        // Con ID = UPDATE
        $model2 = VersaModel::dispense('test_models');
        $model2->id = $result1['id'];
        $model2->name = 'Updated Record';
        $result2 = $model2->save();

        static::assertSame('updated', $result2['action']);
    }

    /** Test: convertValueByTypeMapping procesa correctamente */
    public function testConvertValueByTypeMapping(): void
    {
        $model = VersaModel::dispense('test_models');

        // Boolean
        $schema = ['type' => 'boolean'];
        static::assertTrue($model->convertValueByTypeMapping('active', true, $schema));

        // Integer
        $schema = ['type' => 'integer'];
        static::assertSame(42, $model->convertValueByTypeMapping('age', '42', $schema));

        // String
        $schema = ['type' => 'string'];
        static::assertSame('test', $model->convertValueByTypeMapping('name', 'test', $schema));
    }

    /** Test: getUniqueKeys detecta índices únicos */
    public function testGetUniqueKeysDetectsIndexes(): void
    {
        $model = VersaModel::dispense('test_models');
        $uniqueKeys = $model->getUniqueKeys();

        static::assertIsArray($uniqueKeys);
        // La tabla test_models tiene email como UNIQUE
        static::assertContains('email', $uniqueKeys);
    }

    /** Test: smartUpsert usa claves únicas automáticamente */
    public function testSmartUpsertUsesUniqueKeysAutomatically(): void
    {
        // Primera inserción
        $model1 = VersaModel::dispense('test_models');
        $model1->email = 'smart@example.com';
        $model1->name = 'Smart User';
        $result1 = $model1->smartUpsert();

        static::assertSame('inserted', $result1['action']);

        // Segunda inserción debe actualizar (email es unique)
        $model2 = VersaModel::dispense('test_models');
        $model2->email = 'smart@example.com';
        $model2->name = 'Smart User Updated';
        $result2 = $model2->smartUpsert();

        static::assertSame('updated', $result2['action']);
    }

    /** Test: insertOrUpdate funciona correctamente */
    public function testInsertOrUpdateWorksCorrectly(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->email = 'insertorupdate@example.com';
        $model->name = 'First';

        $result = $model->insertOrUpdate(['email'], ['name']);

        static::assertIsArray($result);
        static::assertArrayHasKey('action', $result);
    }

    /** Test: createOrUpdate funciona correctamente */
    public function testCreateOrUpdateWorksCorrectly(): void
    {
        $model = VersaModel::dispense('test_models');
        $model->name = 'Create Or Update';
        $model->email = 'createorupdate@example.com';

        $result = $model->createOrUpdate(['email' => 'createorupdate@example.com'], ['name']);

        static::assertIsArray($result);
        static::assertArrayHasKey('action', $result);
    }
}
