<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\SchemaBuilder;
use VersaORM\Schema\VersaSchema;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Test básico para el nuevo SchemaBuilder.
 *
 * @group postgresql
 */
class BasicSchemaBuilderTest extends TestCase
{
    private SchemaBuilder $schema;

    private VersaORM $orm;

    protected function setUp(): void
    {
        parent::setUp();

        // Crear una instancia ORM para las pruebas
        $this->orm = new VersaORM([
            'driver' => 'postgresql',
            'host' => $_ENV['DB_HOST'] ?? 'localhost',
            'database' => $_ENV['DB_NAME'] ?? 'versaorm_test',
            'username' => $_ENV['DB_USER'] ?? 'local',
            'password' => $_ENV['DB_PASS'] ?? 'local',
            'charset' => 'utf8',
            'port' => $_ENV['DB_PORT'] ?? 5432,
            'debug' => true,
            'freeze' => false,
        ]);

        $this->schema = $this->orm->schemaBuilder();
        VersaModel::setORM($this->orm);
        VersaSchema::setORM($this->orm);
    }

    protected function tearDown(): void
    {
        try {
            $this->schema->dropIfExists('test_users');
            $this->schema->dropIfExists('test_posts');
            $this->schema->dropIfExists('channels');
            $this->schema->dropIfExists('versa_migrations');
            $this->schema->dropIfExists('advanced_example');
        } catch (\Exception $e) {
            // Ignorar errores de limpieza
        }
        parent::tearDown();
    }

    public function testCanCreateBasicTable(): void
    {
        $this->schema->create('test_users', function ($table) {
            $table->id();
            $table->string('name');
            $table->string('email', 100)->unique();
            $table->timestamps();
        });

        $this->assertTrue(true);
    }

    public function testCanCreateTableWithDifferentTypes(): void
    {
        $this->schema->create('test_posts', function ($table) {
            $table->id();
            $table->string('title', 200);
            $table->text('content');
            $table->integer('views')->default(0);
            $table->boolean('published')->default(false);
            $table->decimal('price', 8, 2)->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('published_at')->nullable();
            $table->timestamps();
        });

        $this->assertTrue(true);
    }

    public function testCanCreateChannelsTable(): void
    {
        $this->schema->create(
            'channels',
            function ($table) {
                $table->id();
                $table->string('codigo_interno', 255);
                $table->string('nombre', 255);
                $table->string('imagen', 255)->nullable();
                $table->boolean('required_register')->default(false);
                $table->json('settings')->nullable();
                $table->timestamps();
            },
            true,
        ); // IF NOT EXISTS

        $this->assertTrue(true);
    }

    public function testCanInsertAndValidateChatbotChannelsData(): void
    {
        // Crear la tabla primero
        $this->schema->create(
            'channels',
            function ($table) {
                $table->id();
                $table->string('codigo_interno', 255);
                $table->string('nombre', 255);
                $table->string('imagen', 255)->nullable();
                $table->boolean('required_register')->default(false);
                $table->json('settings')->nullable();
                $table->timestamps();
            },
            true,
        ); // IF NOT EXISTS

        // Limpiar la tabla antes de la prueba
        $this->orm->table('channels')->delete();

        // Insertar primer registro
        $channel1 = VersaModel::dispense('channels');
        $channel1->codigo_interno = 'CH001';
        $channel1->nombre = 'Canal Principal';
        $channel1->imagen = 'https://example.com/image1.jpg';
        $channel1->settings = json_encode(['theme' => 'dark', 'language' => 'es']);
        $id1 = $channel1->store();

        // Verificar que se guardó y el ID se asignó
        $this->assertIsInt($id1);
        $this->assertEquals(1, $id1);

        // Recargar el registro desde la base de datos
        $savedChannel1 = VersaModel::load('channels', $id1);
        $this->assertNotNull($savedChannel1);
        $this->assertEquals('CH001', $savedChannel1->codigo_interno);
        $this->assertEquals('Canal Principal', $savedChannel1->nombre);
        $this->assertEquals('https://example.com/image1.jpg', $savedChannel1->imagen);
        $this->assertEquals(false, $savedChannel1->required_register); // valor por defecto
        // Verificar settings JSON
        $expectedSettings = ['theme' => 'dark', 'language' => 'es'];
        if (is_string($savedChannel1->settings)) {
            $this->assertEquals($expectedSettings, json_decode($savedChannel1->settings, true));
        } else {
            $this->assertEquals($expectedSettings, $savedChannel1->settings);
        }

        // Verificar timestamps
        $this->assertNotNull($savedChannel1->created_at);
        $this->assertNotNull($savedChannel1->updated_at);
        $this->assertInstanceOf(
            \DateTime::class,
            $savedChannel1->created_at instanceof \DateTime
                ? $savedChannel1->created_at
                : new \DateTime($savedChannel1->created_at),
        );
        $this->assertInstanceOf(
            \DateTime::class,
            $savedChannel1->updated_at instanceof \DateTime
                ? $savedChannel1->updated_at
                : new \DateTime($savedChannel1->updated_at),
        );

        // Insertar segundo registro sin imagen y settings
        $channel2 = VersaModel::dispense('channels');
        $channel2->codigo_interno = 'CH002';
        $channel2->nombre = 'Canal Secundario';
        $id2 = $channel2->store();

        // Verificar ID autoincremental
        $this->assertIsInt($id2);
        $this->assertEquals(2, $id2);

        // Recargar y verificar valores por defecto
        $savedChannel2 = VersaModel::load('channels', $id2);
        $this->assertNotNull($savedChannel2);
        $this->assertEquals('CH002', $savedChannel2->codigo_interno);
        $this->assertEquals('Canal Secundario', $savedChannel2->nombre);
        $this->assertNull($savedChannel2->imagen); // nullable
        $this->assertEquals(false, $savedChannel2->required_register); // valor por defecto
        $this->assertNull($savedChannel2->settings); // nullable

        // Verificar timestamps del segundo registro
        $this->assertNotNull($savedChannel2->created_at);
        $this->assertNotNull($savedChannel2->updated_at);
        $this->assertInstanceOf(
            \DateTime::class,
            $savedChannel2->created_at instanceof \DateTime
                ? $savedChannel2->created_at
                : new \DateTime($savedChannel2->created_at),
        );
        $this->assertInstanceOf(
            \DateTime::class,
            $savedChannel2->updated_at instanceof \DateTime
                ? $savedChannel2->updated_at
                : new \DateTime($savedChannel2->updated_at),
        );

        // Verificar que created_at y updated_at son diferentes entre registros
        $this->assertNotEquals($savedChannel1->created_at, $savedChannel2->created_at);

        // Verificar conteo total de registros
        $allChannels = VersaModel::findAll('channels');
        $this->assertCount(2, $allChannels);
    }

    public function testCanInsertManyWithTimestamps(): void
    {
        // Crear la tabla primero
        $this->schema->create(
            'channels',
            function ($table) {
                $table->id();
                $table->string('codigo_interno', 255);
                $table->string('nombre', 255);
                $table->string('imagen', 255)->nullable();
                $table->boolean('required_register')->default(false);
                $table->json('settings')->nullable();
                $table->timestamps();
            },
            true,
        ); // IF NOT EXISTS

        // Limpiar la tabla antes de la prueba usando TRUNCATE para resetear IDs
        $this->orm->exec('TRUNCATE TABLE channels RESTART IDENTITY');

        // Verificar que la tabla está vacía
        $initialCount = $this->orm->table('channels')->count();
        $this->assertEquals(0, $initialCount, 'La tabla debe estar vacía antes de la prueba');

        // Datos para inserción masiva SIN timestamps manuales (timestamps automáticos)
        $channelsData = [
            [
                'codigo_interno' => 'CH_BULK_001',
                'nombre' => 'Canal Bulk 1',
                'imagen' => 'https://example.com/bulk1.jpg',
                'required_register' => true,
                'settings' => json_encode(['theme' => 'light', 'auto_reply' => true]),
            ],
            [
                'codigo_interno' => 'CH_BULK_002',
                'nombre' => 'Canal Bulk 2',
                'imagen' => null, // nullable
                'required_register' => false, // valor por defecto
                'settings' => json_encode(['theme' => 'dark', 'notifications' => false]),
            ],
            [
                'codigo_interno' => 'CH_BULK_003',
                'nombre' => 'Canal Bulk 3',
                'imagen' => 'https://example.com/bulk3.jpg',
                'required_register' => true,
                'settings' => null, // nullable
            ],
        ];

        // Insertar múltiples registros usando insertMany
        $result = $this->orm->table('channels')->insertMany($channelsData);

        // Verificar que se insertaron correctamente
        // insertMany puede devolver un array con información del resultado
        $this->assertIsArray($result, 'insertMany debe devolver un array');

        // Verificar que los registros se insertaron contando en la base de datos
        $totalAfterInsert = $this->orm->table('channels')->count();
        $this->assertEquals(3, $totalAfterInsert, 'Debe haber exactamente 3 registros después de insertMany');

        // Cargar todos los registros insertados y verificar timestamps
        $insertedChannels = $this->orm
            ->table('channels')
            ->whereIn('codigo_interno', ['CH_BULK_001', 'CH_BULK_002', 'CH_BULK_003'])
            ->orderBy('id', 'ASC')
            ->get();

        // Debug: mostrar todos los registros para entender el problema
        $allChannels = $this->orm->table('channels')->get();
        $this->assertCount(
            3,
            $insertedChannels,
            sprintf(
                'Esperaba 3 registros con códigos bulk, pero encontré %d. Total en tabla: %d',
                count($insertedChannels),
                count($allChannels),
            ),
        );

        foreach ($insertedChannels as $index => $channel) {
            // Verificar datos básicos
            $this->assertEquals($channelsData[$index]['codigo_interno'], $channel['codigo_interno']);
            $this->assertEquals($channelsData[$index]['nombre'], $channel['nombre']);
            $this->assertEquals($channelsData[$index]['imagen'], $channel['imagen']);
            $this->assertEquals($channelsData[$index]['required_register'], $channel['required_register']);

            // Verificar timestamps que deben haberse generado automáticamente
            $this->assertNotNull($channel['created_at'], "created_at debe estar presente en registro {$index}");
            $this->assertNotNull($channel['updated_at'], "updated_at debe estar presente en registro {$index}");

            // Verificar que los timestamps son strings válidos o objetos DateTime
            $createdAt = $channel['created_at'] instanceof \DateTime
                ? $channel['created_at']->format('Y-m-d H:i:s')
                : $channel['created_at'];
            $updatedAt = $channel['updated_at'] instanceof \DateTime
                ? $channel['updated_at']->format('Y-m-d H:i:s')
                : $channel['updated_at'];

            $this->assertNotEmpty($createdAt, "created_at no debe estar vacío en registro {$index}");
            $this->assertNotEmpty($updatedAt, "updated_at no debe estar vacío en registro {$index}");

            // Verificar que los timestamps son fechas válidas recientes (últimos 10 segundos)
            $createdTimestamp = is_string($createdAt) ? strtotime($createdAt) : $createdAt;
            $updatedTimestamp = is_string($updatedAt) ? strtotime($updatedAt) : $updatedAt;
            $now = time();

            $this->assertGreaterThan(
                $now - 10,
                $createdTimestamp,
                "created_at debe ser reciente (últimos 10 segundos) en registro {$index}",
            );
            $this->assertGreaterThan(
                $now - 10,
                $updatedTimestamp,
                "updated_at debe ser reciente (últimos 10 segundos) en registro {$index}",
            );

            // Verificar settings JSON
            if ($channelsData[$index]['settings'] !== null) {
                $expectedSettings = json_decode($channelsData[$index]['settings'], true);
                if (is_string($channel['settings'])) {
                    $this->assertEquals($expectedSettings, json_decode($channel['settings'], true));
                } else {
                    $this->assertEquals($expectedSettings, $channel['settings']);
                }
            } else {
                $this->assertNull($channel['settings']);
            }
        }

        // Verificar que los timestamps automáticos fueron generados correctamente
        $timestamps = array_column($insertedChannels, 'created_at');
        foreach ($timestamps as $index => $timestamp) {
            $this->assertNotNull($timestamp, "Timestamp created_at debe existir en registro {$index}");

            // Convertir a timestamp Unix para comparación
            $unixTimestamp = $timestamp instanceof \DateTime ? $timestamp->getTimestamp() : strtotime($timestamp);

            // El timestamp debe ser muy reciente (últimos 10 segundos)
            $this->assertGreaterThan(time() - 10, $unixTimestamp, 'Timestamp automático debe ser muy reciente');
        }

        // Verificar conteo total después de insertMany
        $totalChannels = $this->orm->table('channels')->count();
        $this->assertEquals(3, $totalChannels);
    }

    public function testMigrateFromOldSchemaCreateToNewSchemaBuilder(): void
    {
        // ============================================================================
        // DEMOSTRACIÓN: Migración del método schemaCreate() antiguo al nuevo SchemaBuilder
        // ============================================================================

        // ❌ MÉTODO ANTIGUO (así se creaban las tablas antes):
        // $this->orm->schemaCreate(
        //     'versa_migrations',
        //     [
        //         [
        //             'name' => 'id',
        //             'type' => 'INT',
        //             'primary' => true,
        //             'autoIncrement' => true,
        //             'nullable' => false,
        //         ],
        //         ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
        //         [
        //             'name' => 'created_at',
        //             'type' => 'TIMESTAMP',
        //             'default' => 'CURRENT_TIMESTAMP',
        //         ],
        //     ],
        //     [
        //         'engine' => 'InnoDB',
        //         'if_not_exists' => true,
        //     ],
        // );

        // ✅ MÉTODO NUEVO con SchemaBuilder (más limpio y mantenible):
        $this->schema->create(
            'versa_migrations',
            function ($table) {
                // Clave primaria autoincremental (equivale a: INT PRIMARY KEY AUTO_INCREMENT NOT NULL)
                $table->id();

                // String no nullable (equivale a: VARCHAR(255) NOT NULL)
                $table->string('name', 255)->nullable(false);

                // Opcional: agregar más campos comunes en migraciones
                $table->text('description')->nullable();
                $table->integer('batch')->default(1);
                $table->timestamp('executed_at')->nullable();

                // Timestamps automáticos (created_at y updated_at con valores automáticos)
                $table->timestamps();

                // Índices
                $table->index('name');
                $table->unique(['name', 'batch']);
            },
            true,
        ); // true = IF NOT EXISTS (equivale a 'if_not_exists' => true)

        // Verificar que la tabla se creó correctamente
        $tables = $this->orm->schema('tables');
        $this->assertContains('versa_migrations', $tables);

        // Probar inserción de datos
        $migrationData = [
            'name' => 'create_users_table',
            'description' => 'Migración para crear tabla de usuarios',
            'batch' => 1,
            'executed_at' => date('Y-m-d H:i:s'),
        ];

        $insertResult = $this->orm->table('versa_migrations')->insert($migrationData);
        $this->assertNotNull($insertResult);

        // Verificar que se insertó con timestamps automáticos
        $migration = $this->orm->table('versa_migrations')->firstArray();
        $this->assertNotNull($migration);
        $this->assertEquals('create_users_table', $migration['name']);
        $this->assertEquals('Migración para crear tabla de usuarios', $migration['description']);
        $this->assertEquals(1, $migration['batch']);

        // Verificar timestamps automáticos
        $this->assertNotNull($migration['created_at']);
        $this->assertNotNull($migration['updated_at']);

        // ============================================================================
        // EJEMPLO AVANZADO: Tabla con relaciones y constraints
        // ============================================================================

        $this->schema->create(
            'advanced_example',
            function ($table) {
                // Clave primaria
                $table->id();

                // Campos básicos
                $table->string('title', 200)->nullable(false);
                $table->text('content');
                $table->decimal('price', 10, 2)->default(0.00);
                $table->boolean('is_active')->default(true);
                $table->json('metadata')->nullable();

                // Ejemplo de clave foránea (comentado porque la tabla 'categories' no existe en este test)
                // $table->integer('category_id')->unsigned();
                // $table->foreign('category_id')->references('id')->on('categories')->onDelete('cascade');

                // Timestamps automáticos
                $table->timestamps();

                // Índices optimizados
                $table->index(['is_active', 'created_at']);
                $table->fulltext(['title', 'content']); // Solo para motores que lo soporten
            },
            true,
        );

        // Verificar que la tabla avanzada se creó
        $tables = $this->orm->schema('tables');
        $this->assertContains('advanced_example', $tables);

        // ============================================================================
        // VENTAJAS DEL NUEVO MÉTODO:
        // ============================================================================
        // 1. API fluida y legible
        // 2. Tipado fuerte y autocompletado en IDEs
        // 3. Abstracción automática entre motores de BD
        // 4. Timestamps automáticos (gracias al fix implementado)
        // 5. Menos propenso a errores (no más arrays con claves incorrectas)
        // 6. Soporte nativo para relaciones y constraints
        // 7. Sintaxis similar a Laravel Migrations (familiaridad)

        $this->assertTrue(true, 'Migración del antiguo schemaCreate() al nuevo SchemaBuilder completada exitosamente');
    }
}
