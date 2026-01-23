<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\VersaSchema;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Tests comprehensivos para VersaSchema facade.
 *
 * @group unit
 * @group schema
 */
final class VersaSchemaTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'freeze' => false,
        ]);

        VersaModel::setORM($this->orm);
        VersaSchema::setORM($this->orm);
    }

    protected function tearDown(): void
    {
        try {
            VersaSchema::dropIfExists('test_table');
            VersaSchema::dropIfExists('test_users');
            VersaSchema::dropIfExists('test_renamed');
        } catch (\Exception) {
            // Ignorar errores de limpieza
        }
    }

    public function test_set_orm_configures_instance(): void
    {
        $newOrm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaSchema::setORM($newOrm);

        // Verificar que puede crear una tabla (lo cual requiere ORM configurado)
        VersaSchema::create('test_table', static function ($table) {
            $table->id();
        });

        static::assertTrue(VersaSchema::hasTable('test_table'));
    }

    public function test_create_table_with_basic_columns(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('name');
            $table->string('email');
            $table->timestamps();
        });

        static::assertTrue(VersaSchema::hasTable('test_users'));
    }

    public function test_create_table_if_not_exists(): void
    {
        VersaSchema::create(
            'test_users',
            static function ($table) {
                $table->id();
                $table->string('name');
            },
            true,
        );

        // Crear de nuevo con if_not_exists no debe lanzar excepción
        VersaSchema::create(
            'test_users',
            static function ($table) {
                $table->id();
                $table->string('name');
            },
            true,
        );

        static::assertTrue(VersaSchema::hasTable('test_users'));
    }

    public function test_table_modifies_existing_table(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('name');
        });

        VersaSchema::table('test_users', static function ($table) {
            $table->string('email')->nullable();
        });

        static::assertTrue(VersaSchema::hasColumn('test_users', 'email'));
    }

    public function test_rename_table(): void
    {
        VersaSchema::create('test_table', static function ($table) {
            $table->id();
        });

        VersaSchema::rename('test_table', 'test_renamed');

        static::assertFalse(VersaSchema::hasTable('test_table'));
        static::assertTrue(VersaSchema::hasTable('test_renamed'));
    }

    public function test_drop_table(): void
    {
        VersaSchema::create('test_table', static function ($table) {
            $table->id();
        });

        static::assertTrue(VersaSchema::hasTable('test_table'));

        VersaSchema::drop('test_table');

        static::assertFalse(VersaSchema::hasTable('test_table'));
    }

    public function test_drop_if_exists_when_table_exists(): void
    {
        VersaSchema::create('test_table', static function ($table) {
            $table->id();
        });

        VersaSchema::dropIfExists('test_table');

        static::assertFalse(VersaSchema::hasTable('test_table'));
    }

    public function test_drop_if_exists_when_table_not_exists(): void
    {
        // No debe lanzar excepción
        VersaSchema::dropIfExists('non_existent_table');

        static::assertFalse(VersaSchema::hasTable('non_existent_table'));
    }

    public function test_has_table_returns_true_when_exists(): void
    {
        VersaSchema::create('test_table', static function ($table) {
            $table->id();
        });

        static::assertTrue(VersaSchema::hasTable('test_table'));
    }

    public function test_has_table_returns_false_when_not_exists(): void
    {
        static::assertFalse(VersaSchema::hasTable('non_existent_table'));
    }

    public function test_has_column_returns_true_when_exists(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('name');
            $table->string('email');
        });

        static::assertTrue(VersaSchema::hasColumn('test_users', 'name'));
        static::assertTrue(VersaSchema::hasColumn('test_users', 'email'));
    }

    public function test_has_column_returns_false_when_not_exists(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('name');
        });

        static::assertFalse(VersaSchema::hasColumn('test_users', 'non_existent_column'));
    }

    public function test_has_index_returns_true_when_exists(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('email')->index();
        });

        static::assertTrue(VersaSchema::hasIndex('test_users', 'email'));
    }

    public function test_has_index_with_array_of_columns(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('first_name');
            $table->string('last_name');
            $table->index(['first_name', 'last_name']);
        });

        static::assertTrue(VersaSchema::hasIndex('test_users', ['first_name', 'last_name']));
    }

    public function test_get_column_listing_returns_column_names(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('name');
            $table->string('email');
        });

        $columns = VersaSchema::getColumnListing('test_users');

        static::assertIsArray($columns);
        static::assertContains('id', $columns);
        static::assertContains('name', $columns);
        static::assertContains('email', $columns);
    }

    public function test_get_columns_returns_detailed_info(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('name');
        });

        $columns = VersaSchema::getColumns('test_users');

        static::assertIsArray($columns);
        static::assertNotEmpty($columns);
    }

    public function test_get_indexes_returns_table_indexes(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
            $table->string('email')->index();
        });

        $indexes = VersaSchema::getIndexes('test_users');

        static::assertIsArray($indexes);
    }

    public function test_get_foreign_keys_returns_foreign_key_info(): void
    {
        VersaSchema::create('test_users', static function ($table) {
            $table->id();
        });

        $foreignKeys = VersaSchema::getForeignKeys('test_users');

        static::assertIsArray($foreignKeys);
    }

    public function test_disable_foreign_key_constraints(): void
    {
        // No debe lanzar excepción
        VersaSchema::disableForeignKeyConstraints();

        static::assertTrue(true);
    }

    public function test_enable_foreign_key_constraints(): void
    {
        // No debe lanzar excepción
        VersaSchema::enableForeignKeyConstraints();

        static::assertTrue(true);
    }

    public function test_without_foreign_key_constraints_executes_callback(): void
    {
        $executed = false;

        $result = VersaSchema::withoutForeignKeyConstraints(static function () use (&$executed) {
            $executed = true;

            return 'result';
        });

        static::assertTrue($executed);
        static::assertSame('result', $result);
    }

    public function test_connection_throws_not_supported_exception(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Multiple database connections are not yet supported');

        VersaSchema::connection('other');
    }
}
