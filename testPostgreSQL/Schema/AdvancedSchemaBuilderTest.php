<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\SchemaBuilder;
use VersaORM\Schema\VersaSchema;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Test completo para el SchemaBuilder incluyendo funcionalidades avanzadas.
 *
 * @group postgresql
 */
class AdvancedSchemaBuilderTest extends TestCase
{
    private SchemaBuilder $schema;

    private VersaORM $orm;

    protected function setUp(): void
    {
        parent::setUp();

        $this->orm = new VersaORM([
            'driver' => 'postgresql',
            'host' => getenv('DB_HOST') ?: 'localhost',
            'database' => getenv('DB_NAME') ?: 'versaorm_test',
            'username' => getenv('DB_USER') ?: 'local',
            'password' => getenv('DB_PASS') ?: 'local',
            'charset' => 'utf8',
            'port' => (int) (getenv('DB_PORT') ?: 5432),
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

    /**
     * Afirma que la tabla existe y declara las columnas indicadas.
     *
     * Estos tests creaban tablas y terminaban en assertTrue(true), así que no
     * verificaban nada: una generación de DDL que perdiera una columna, un índice o un
     * ALTER pasaba igual. Se comprueban nombres (no tipos) porque el mapeo de tipos
     * difiere por motor y ya tiene sus propios tests.
     *
     * @param list<string> $columns
     */
    private function assertTableHasColumns(string $table, array $columns): void
    {
        $schema = $this->orm->schema('columns', $table);
        static::assertIsArray($schema);
        static::assertNotEmpty($schema, sprintf('la tabla %s no existe o no tiene columnas', $table));
        $names = [];

        foreach ($schema as $column) {
            $name = $column['column_name'] ?? $column['name'] ?? null;

            if (is_string($name)) {
                $names[] = strtolower($name);
            }
        }

        foreach ($columns as $expected) {
            static::assertContains(
                strtolower($expected),
                $names,
                sprintf('%s no declara la columna %s. Tiene: %s', $table, $expected, implode(', ', $names)),
            );
        }
    }

    private function assertTableExists(string $table, bool $exists = true): void
    {
        $tables = $this->orm->schema('tables');
        static::assertIsArray($tables);
        $normalized = array_map('strtolower', array_map('strval', $tables));

        if ($exists) {
            static::assertContains(strtolower($table), $normalized, sprintf('%s debería existir', $table));

            return;
        }
        static::assertNotContains(strtolower($table), $normalized, sprintf('%s no debería existir', $table));
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

        $this->assertTableHasColumns('test_products', [
            'id',
            'name',
            'sku',
            'description',
            'price',
            'stock',
            'active',
            'created_at',
            'updated_at',
        ]);

        // Los índices declarados tienen que haber llegado al esquema.
        $indexes = $this->orm->schema('indexes', 'test_products');
        static::assertIsArray($indexes);
        $indexedColumns = [];

        foreach ($indexes as $index) {
            $indexedColumns[] = implode(',', array_map('strtolower', (array) ($index['columns'] ?? [])));
        }
        static::assertContains('name', $indexedColumns, json_encode($indexedColumns));
        static::assertContains('name,active', $indexedColumns, json_encode($indexedColumns));
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

        $this->assertTableHasColumns('test_categories', ['id', 'name', 'slug']);
        $this->assertTableHasColumns('test_products', ['id', 'name', 'category_id', 'price']);

        $keys = $this->orm->schema('foreign_keys', 'test_products');
        static::assertIsArray($keys);
        $match = null;

        foreach ($keys as $key) {
            if (strtolower((string) ($key['column'] ?? '')) !== 'category_id') {
                continue;
            }

            $match = $key;
            break;
        }
        static::assertNotNull($match, 'test_products no declara la clave foránea sobre category_id');
        static::assertSame('test_categories', strtolower((string) ($match['foreign_table'] ?? '')));
        static::assertSame('CASCADE', strtoupper((string) ($match['on_delete'] ?? '')));
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

        $this->assertTableHasColumns('test_users', [
            'id',
            'name',
            'email',
            'email_verified_at',
            'password',
            'remember_token',
            'created_at',
            'updated_at',
        ]);
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

        // Lo esencial del test: el ALTER añadió las tres columnas nuevas y conservó las
        // originales.
        $this->assertTableHasColumns('test_orders', [
            'id',
            'order_number',
            'total',
            'created_at',
            'updated_at',
            'status',
            'user_id',
            'metadata',
        ]);
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

        $this->assertTableHasColumns('test_users', [
            'id',
            'name',
            'email',
            'preferences',
            'birthdate',
            'preferred_contact_time',
            'is_active',
            'role',
            'balance',
            'created_at',
            'updated_at',
        ]);
    }

    public function testCanDropTables(): void
    {
        // Crear una tabla temporal
        $this->schema->create('test_temp_table', static function ($table) {
            $table->id();
            $table->string('data');
        });

        $this->assertTableExists('test_temp_table');

        // Eliminarla
        $this->schema->drop('test_temp_table');

        // El test no comprobaba que la tabla desapareciera: un drop() que no hiciera
        // nada pasaba igual.
        $this->assertTableExists('test_temp_table', false);
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

        $this->assertTableHasColumns('test_cross_engine', [
            'id',
            'text_field',
            'number_field',
            'flag_field',
            'json_field',
            'money_field',
            'time_field',
        ]);

        // Limpiar
        $this->schema->dropIfExists('test_cross_engine');
    }
}
