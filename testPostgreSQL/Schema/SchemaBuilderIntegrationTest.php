<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\Blueprint;
use VersaORM\Schema\SchemaBuilder;
use VersaORM\VersaORM;

/**
 * Tests de integración para SchemaBuilder con PostgreSQL.
 */
class SchemaBuilderIntegrationTest extends TestCase
{
    private VersaORM $orm;
    private SchemaBuilder $schema;

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

        $this->schema = new SchemaBuilder($this->orm);

        // Limpiar cualquier tabla de test anterior
        $this->cleanupTestTables();
    }

    protected function tearDown(): void
    {
        $this->cleanupTestTables();
    }

    private function cleanupTestTables(): void
    {
        $tables = [
            'test_users',
            'test_posts',
            'test_products',
            'test_orders',
            'test_categories',
            'test_inventory',
        ];

        foreach ($tables as $table) {
            $this->schema->dropIfExists($table);
        }
    }

    public function testCreateTableWithMultipleColumnTypes(): void
    {
        $this->schema->create('test_products', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->text('description');
            $table->decimal('price', 10, 2);
            $table->integer('stock')->unsigned();
            $table->boolean('active')->default(true);
            $table->timestamp('created_at')->useCurrent();
            $table->timestamp('updated_at')->useCurrent()->useCurrentOnUpdate();
        });

        static::assertTrue($this->schema->hasTable('test_products'));

        // Verificar columnas
        static::assertTrue($this->schema->hasColumn('test_products', 'id'));
        static::assertTrue($this->schema->hasColumn('test_products', 'name'));
        static::assertTrue($this->schema->hasColumn('test_products', 'description'));
        static::assertTrue($this->schema->hasColumn('test_products', 'price'));
        static::assertTrue($this->schema->hasColumn('test_products', 'stock'));
        static::assertTrue($this->schema->hasColumn('test_products', 'active'));
        static::assertTrue($this->schema->hasColumn('test_products', 'created_at'));
        static::assertTrue($this->schema->hasColumn('test_products', 'updated_at'));
    }

    public function testCreateTableWithIndexes(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100)->unique();
            $table->string('username', 50)->index();
            $table->string('first_name', 50);
            $table->string('last_name', 50);
            $table->index(['first_name', 'last_name'], 'idx_full_name');
        });

        static::assertTrue($this->schema->hasTable('test_users'));

        // Verificar índices
        static::assertTrue($this->schema->hasIndex('test_users', ['email']));
        static::assertTrue($this->schema->hasIndex('test_users', ['username']));
        static::assertTrue($this->schema->hasIndex('test_users', ['first_name', 'last_name']));
    }

    public function testCreateTableWithForeignKeys(): void
    {
        // Crear tabla padre
        $this->schema->create('test_categories', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
        });

        // Crear tabla hija con FK
        $this->schema->create('test_posts', static function (Blueprint $table) {
            $table->id();
            $table->string('title', 200);
            $table->text('content');
            $table->foreignId('category_id')->constrained('test_categories')->cascadeOnDelete();
        });

        static::assertTrue($this->schema->hasTable('test_posts'));
        static::assertTrue($this->schema->hasColumn('test_posts', 'category_id'));

        // Verificar FK
        $foreignKeys = $this->schema->getForeignKeys('test_posts');
        static::assertNotEmpty($foreignKeys);
        static::assertCount(1, $foreignKeys);
    }

    public function testAlterTableAddColumns(): void
    {
        // Crear tabla básica
        $this->schema->create('test_orders', static function (Blueprint $table) {
            $table->id();
            $table->string('order_number', 50);
        });

        // Alterar: agregar columnas
        $this->schema->table('test_orders', static function (Blueprint $table) {
            $table->decimal('total', 10, 2);
            $table->string('status', 20)->default('pending');
            $table->timestamp('completed_at')->nullable();
        });

        // Verificar nuevas columnas
        static::assertTrue($this->schema->hasColumn('test_orders', 'total'));
        static::assertTrue($this->schema->hasColumn('test_orders', 'status'));
        static::assertTrue($this->schema->hasColumn('test_orders', 'completed_at'));
    }

    public function testAlterTableModifyColumn(): void
    {
        $this->schema->create('test_inventory', static function (Blueprint $table) {
            $table->id();
            $table->string('sku', 50);
            $table->integer('quantity');
        });

        // Cambiar tipo de columna
        $this->schema->table('test_inventory', static function (Blueprint $table) {
            $table->string('sku', 100)->change();
        });

        $columns = $this->schema->getColumns('test_inventory');
        $skuColumn = array_filter($columns, static fn($col) => $col['name'] === 'sku');
        static::assertNotEmpty($skuColumn);
    }

    public function testAlterTableDropColumn(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->string('temp_field', 50);
        });

        static::assertTrue($this->schema->hasColumn('test_users', 'temp_field'));

        // Eliminar columna
        $this->schema->table('test_users', static function (Blueprint $table) {
            $table->dropColumn('temp_field');
        });

        static::assertFalse($this->schema->hasColumn('test_users', 'temp_field'));
    }

    public function testAlterTableRenameColumn(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('old_name', 100);
        });

        static::assertTrue($this->schema->hasColumn('test_users', 'old_name'));

        // Renombrar columna
        $this->schema->table('test_users', static function (Blueprint $table) {
            $table->renameColumn('old_name', 'new_name');
        });

        static::assertFalse($this->schema->hasColumn('test_users', 'old_name'));
        static::assertTrue($this->schema->hasColumn('test_users', 'new_name'));
    }

    public function testRenameTable(): void
    {
        $this->schema->create('test_old_table', static function (Blueprint $table) {
            $table->id();
            $table->string('data', 100);
        });

        static::assertTrue($this->schema->hasTable('test_old_table'));

        $this->schema->rename('test_old_table', 'test_new_table');

        static::assertFalse($this->schema->hasTable('test_old_table'));
        static::assertTrue($this->schema->hasTable('test_new_table'));

        // Cleanup
        $this->schema->drop('test_new_table');
    }

    public function testDropTable(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100);
        });

        static::assertTrue($this->schema->hasTable('test_users'));

        $this->schema->drop('test_users');

        static::assertFalse($this->schema->hasTable('test_users'));
    }

    public function testDropTableIfExists(): void
    {
        // Drop no existente no debe lanzar error
        $this->schema->dropIfExists('non_existent_table');

        // Crear y drop
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
        });

        static::assertTrue($this->schema->hasTable('test_users'));

        $this->schema->dropIfExists('test_users');

        static::assertFalse($this->schema->hasTable('test_users'));
    }

    public function testGetColumnListing(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->string('email', 100);
            $table->timestamp('created_at');
        });

        $columns = $this->schema->getColumnListing('test_users');

        static::assertIsArray($columns);
        static::assertContains('id', $columns);
        static::assertContains('name', $columns);
        static::assertContains('email', $columns);
        static::assertContains('created_at', $columns);
    }

    public function testGetColumnsDetailed(): void
    {
        $this->schema->create('test_products', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100)->nullable();
            $table->decimal('price', 10, 2)->default(0);
        });

        $columns = $this->schema->getColumns('test_products');

        static::assertIsArray($columns);
        static::assertNotEmpty($columns);

        foreach ($columns as $column) {
            static::assertArrayHasKey('name', $column);
            static::assertArrayHasKey('type', $column);
        }
    }

    public function testGetIndexes(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100)->unique();
            $table->string('username', 50)->index();
        });

        $indexes = $this->schema->getIndexes('test_users');

        static::assertIsArray($indexes);
        static::assertNotEmpty($indexes);
    }

    public function testCreateTableWithJsonColumn(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->json('metadata')->nullable();
            $table->jsonb('preferences')->nullable();
        });

        static::assertTrue($this->schema->hasColumn('test_users', 'metadata'));
        static::assertTrue($this->schema->hasColumn('test_users', 'preferences'));
    }

    public function testCreateTableWithArrayColumns(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('tags', 50)->array()->nullable();
        });

        static::assertTrue($this->schema->hasColumn('test_users', 'tags'));
    }

    public function testCreateTableWithInetColumn(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->ipAddress('last_ip')->nullable();
        });

        static::assertTrue($this->schema->hasColumn('test_users', 'last_ip'));
    }

    public function testCreateTableWithUuidColumn(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('name', 100);
        });

        static::assertTrue($this->schema->hasColumn('test_users', 'id'));
    }

    public function testCreateTableWithTimestamps(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->timestamps();
        });

        static::assertTrue($this->schema->hasColumn('test_users', 'created_at'));
        static::assertTrue($this->schema->hasColumn('test_users', 'updated_at'));
    }

    public function testCreateTableWithSoftDeletes(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->softDeletes();
        });

        static::assertTrue($this->schema->hasColumn('test_users', 'deleted_at'));
    }

    public function testCreateTableWithRememberToken(): void
    {
        $this->schema->create('test_users', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100);
            $table->rememberToken();
        });

        static::assertTrue($this->schema->hasColumn('test_users', 'remember_token'));
    }
}
