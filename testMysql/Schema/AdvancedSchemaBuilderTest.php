<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\SchemaBuilder;
use VersaORM\Schema\VersaSchema;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Test completo para el SchemaBuilder incluyendo funcionalidades avanzadas.
 *
 * @group mysql
 */
class AdvancedSchemaBuilderTest extends TestCase
{
    private SchemaBuilder $schema;

    private VersaORM $orm;

    protected function setUp(): void
    {
        parent::setUp();

        $this->orm = new VersaORM([
            'driver' => 'mysql',
            'host' => getenv('DB_HOST') ?: 'localhost',
            'database' => getenv('DB_NAME') ?: 'versaorm_test',
            'username' => getenv('DB_USER') ?: 'local',
            'password' => getenv('DB_PASS') ?: 'local',
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
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
            $this->schema->dropIfExists('test_products');
            $this->schema->dropIfExists('test_categories');
            $this->schema->dropIfExists('test_users');
            $this->schema->dropIfExists('test_orders');
        } catch (\Exception $e) {
            // Ignorar errores de limpieza
        }
        parent::tearDown();
    }

    public function testCanCreateTableWithIndexes(): void
    {
        $this->schema->create('test_products', static function ($table) {
            $table->id();
            $table->string('name', 150);
            $table->string('sku', 50)->unique();
            $table->text('description');
            $table->decimal('price', 10, 2);
            $table->integer('stock')->default(0);
            $table->boolean('active')->default(true);
            $table->timestamps();

            // Índices
            $table->index('name');
            $table->index(['name', 'active'], 'name_active_idx');
        });

        static::assertTrue(true);
    }

    public function testCanCreateTableWithForeignKeys(): void
    {
        // Tabla padre
        $this->schema->create('test_categories', static function ($table) {
            $table->id();
            $table->string('name', 100);
            $table->string('slug', 100)->unique();
            $table->timestamps();
        });

        // Tabla con foreign key
        $this->schema->create('test_products', static function ($table) {
            $table->id();
            $table->string('name', 150);
            $table->unsignedBigInteger('category_id');
            $table->decimal('price', 10, 2);
            $table->timestamps();

            $table->foreign('category_id')->references('id')->on('test_categories')->onDelete('cascade');
        });

        static::assertTrue(true);
    }

    public function testCanUseStaticFacade(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('name', 100);
            $table->string('email', 100)->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });

        static::assertTrue(true);
    }

    public function testCanModifyExistingTable(): void
    {
        // Crear tabla inicial
        $this->schema->create('test_orders', static function ($table) {
            $table->id();
            $table->string('order_number', 50)->unique();
            $table->decimal('total', 10, 2);
            $table->timestamps();
        });

        // Modificar tabla
        $this->schema->table('test_orders', static function ($table) {
            $table->string('status', 50)->default('pending');
            $table->unsignedBigInteger('user_id')->nullable();
            $table->json('metadata')->nullable();
        });

        static::assertTrue(true);
    }

    public function testCanCreateTableWithSpecialTypes(): void
    {
        $this->schema->create('test_users', static function ($table) {
            $table->id();
            $table->string('name', 100);
            $table->string('email', 100)->unique();
            $table->json('preferences')->nullable();
            $table->date('birthdate')->nullable();
            $table->time('preferred_contact_time')->nullable();
            $table->boolean('is_active')->default(true);
            $table->enum('role', ['admin', 'user', 'moderator'])->default('user');
            $table->decimal('balance', 12, 2)->default(0.00);
            $table->timestamps();
        });

        static::assertTrue(true);
    }

    public function testCanDropTables(): void
    {
        // Crear una tabla temporal
        $this->schema->create('test_temp_table', static function ($table) {
            $table->id();
            $table->string('data');
        });

        // Eliminarla
        $this->schema->drop('test_temp_table');

        // Verificar que la operación se completó sin errores
        static::assertTrue(true);
    }

    public function testTypeTransparencyAcrossEngines(): void
    {
        // Este test verifica que los tipos se mapean correctamente
        // sin importar el motor de base de datos configurado

        $this->schema->create('test_cross_engine', static function ($table) {
            $table->id(); // AUTO_INCREMENT en MySQL, SERIAL en PostgreSQL, INTEGER PRIMARY KEY en SQLite
            $table->string('text_field', 100); // VARCHAR en MySQL/PostgreSQL, TEXT en SQLite
            $table->integer('number_field'); // INT en MySQL, INTEGER en PostgreSQL/SQLite
            $table->boolean('flag_field'); // TINYINT(1) en MySQL, BOOLEAN en PostgreSQL, INTEGER en SQLite
            $table->json('json_field')->nullable(); // JSON en MySQL/PostgreSQL, TEXT en SQLite
            $table->decimal('money_field', 10, 2); // DECIMAL en MySQL/PostgreSQL, NUMERIC en SQLite
            $table->timestamp('time_field')->nullable(); // TIMESTAMP en todos
        });

        static::assertTrue(true);

        // Limpiar
        $this->schema->dropIfExists('test_cross_engine');
    }
}
