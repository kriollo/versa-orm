<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\Blueprint;
use VersaORM\Schema\SchemaBuilder;
use VersaORM\VersaORM;

/**
 * Tests unitarios adicionales para SchemaBuilder.
 */
class SchemaBuilderUnitTest extends TestCase
{
    private VersaORM $orm;
    private SchemaBuilder $schema;

    protected function setUp(): void
    {
        // Usar SQLite en memoria para tests unitarios rápidos
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]);

        $this->schema = new SchemaBuilder($this->orm);
    }

    public function testCreateTableWithCallback(): void
    {
        $callbackInvoked = false;

        $this->schema->create('test_table', static function (Blueprint $table) use (&$callbackInvoked) {
            $callbackInvoked = true;
            $table->id();
            $table->string('name', 100);
        });

        static::assertTrue($callbackInvoked);
        static::assertTrue($this->schema->hasTable('test_table'));
    }

    public function testTableMethodForAltering(): void
    {
        $this->schema->create('existing_table', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
        });

        $callbackInvoked = false;

        $this->schema->table('existing_table', static function (Blueprint $table) use (&$callbackInvoked) {
            $callbackInvoked = true;
            $table->string('email', 100);
        });

        static::assertTrue($callbackInvoked);
        static::assertTrue($this->schema->hasColumn('existing_table', 'email'));
    }

    public function testCreateIfNotExists(): void
    {
        $this->schema->createIfNotExists('new_table', static function (Blueprint $table) {
            $table->id();
        });

        static::assertTrue($this->schema->hasTable('new_table'));

        // Segunda llamada no debe fallar
        $this->schema->createIfNotExists('new_table', static function (Blueprint $table) {
            $table->id();
        });

        static::assertTrue($this->schema->hasTable('new_table'));
    }

    public function testDropIfExistsDoesNotFailOnNonExistent(): void
    {
        // No debe lanzar excepción
        $this->schema->dropIfExists('non_existent_table_12345');

        static::assertFalse($this->schema->hasTable('non_existent_table_12345'));
    }

    public function testHasTableReturnsTrueForExisting(): void
    {
        $this->schema->create('check_table', static function (Blueprint $table) {
            $table->id();
        });

        static::assertTrue($this->schema->hasTable('check_table'));
    }

    public function testHasTableReturnsFalseForNonExisting(): void
    {
        static::assertFalse($this->schema->hasTable('does_not_exist'));
    }

    public function testHasColumnReturnsTrueForExisting(): void
    {
        $this->schema->create('column_table', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
        });

        static::assertTrue($this->schema->hasColumn('column_table', 'name'));
    }

    public function testHasColumnReturnsFalseForNonExisting(): void
    {
        $this->schema->create('column_table', static function (Blueprint $table) {
            $table->id();
        });

        static::assertFalse($this->schema->hasColumn('column_table', 'non_existent'));
    }

    public function testHasIndexWithSingleColumn(): void
    {
        $this->schema->create('index_table', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100)->unique();
        });

        static::assertTrue($this->schema->hasIndex('index_table', ['email']));
    }

    public function testHasIndexWithMultipleColumns(): void
    {
        $this->schema->create('multi_index', static function (Blueprint $table) {
            $table->id();
            $table->string('first_name', 50);
            $table->string('last_name', 50);
            $table->index(['first_name', 'last_name']);
        });

        static::assertTrue($this->schema->hasIndex('multi_index', ['first_name', 'last_name']));
    }

    public function testGetColumnListingReturnsArray(): void
    {
        $this->schema->create('list_table', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->string('email', 100);
        });

        $columns = $this->schema->getColumnListing('list_table');

        static::assertIsArray($columns);
        static::assertNotEmpty($columns);
        static::assertContains('id', $columns);
        static::assertContains('name', $columns);
        static::assertContains('email', $columns);
    }

    public function testGetColumnsReturnsDetailedInfo(): void
    {
        $this->schema->create('detail_table', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100)->nullable();
        });

        $columns = $this->schema->getColumns('detail_table');

        static::assertIsArray($columns);
        static::assertNotEmpty($columns);

        foreach ($columns as $column) {
            static::assertIsArray($column);
            static::assertArrayHasKey('name', $column);
            static::assertArrayHasKey('type', $column);
        }
    }

    public function testGetIndexesReturnsArray(): void
    {
        $this->schema->create('idx_table', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100)->unique();
        });

        $indexes = $this->schema->getIndexes('idx_table');

        static::assertIsArray($indexes);
    }

    public function testGetForeignKeysReturnsArray(): void
    {
        $this->schema->create('parent_table', static function (Blueprint $table) {
            $table->id();
        });

        $this->schema->create('child_table', static function (Blueprint $table) {
            $table->id();
            $table->foreignId('parent_id')->constrained('parent_table');
        });

        $foreignKeys = $this->schema->getForeignKeys('child_table');

        static::assertIsArray($foreignKeys);
    }

    public function testRenameTablePreservesData(): void
    {
        $this->schema->create('old_name', static function (Blueprint $table) {
            $table->id();
            $table->string('data', 100);
        });

        // Insertar datos
        $this->orm->exec("INSERT INTO old_name (data) VALUES ('test')");

        $this->schema->rename('old_name', 'new_name');

        static::assertFalse($this->schema->hasTable('old_name'));
        static::assertTrue($this->schema->hasTable('new_name'));

        // Verificar que los datos se preservaron
        $result = $this->orm->exec('SELECT COUNT(*) as count FROM new_name');
        static::assertSame(1, (int) $result[0]['count']);
    }

    public function testDropTableRemovesTable(): void
    {
        $this->schema->create('drop_test', static function (Blueprint $table) {
            $table->id();
        });

        static::assertTrue($this->schema->hasTable('drop_test'));

        $this->schema->drop('drop_test');

        static::assertFalse($this->schema->hasTable('drop_test'));
    }

    public function testCreateMultipleTables(): void
    {
        $this->schema->create('table1', static function (Blueprint $table) {
            $table->id();
        });

        $this->schema->create('table2', static function (Blueprint $table) {
            $table->id();
        });

        $this->schema->create('table3', static function (Blueprint $table) {
            $table->id();
        });

        static::assertTrue($this->schema->hasTable('table1'));
        static::assertTrue($this->schema->hasTable('table2'));
        static::assertTrue($this->schema->hasTable('table3'));
    }

    public function testAlterTableMultipleTimes(): void
    {
        $this->schema->create('alter_test', static function (Blueprint $table) {
            $table->id();
        });

        $this->schema->table('alter_test', static function (Blueprint $table) {
            $table->string('field1', 50);
        });

        $this->schema->table('alter_test', static function (Blueprint $table) {
            $table->string('field2', 50);
        });

        $this->schema->table('alter_test', static function (Blueprint $table) {
            $table->string('field3', 50);
        });

        static::assertTrue($this->schema->hasColumn('alter_test', 'field1'));
        static::assertTrue($this->schema->hasColumn('alter_test', 'field2'));
        static::assertTrue($this->schema->hasColumn('alter_test', 'field3'));
    }

    public function testComplexSchemaOperations(): void
    {
        // Create parent table
        $this->schema->create('users', static function (Blueprint $table) {
            $table->id();
            $table->string('username', 50)->unique();
            $table->string('email', 100)->unique();
            $table->timestamps();
        });

        // Create related table
        $this->schema->create('posts', static function (Blueprint $table) {
            $table->id();
            $table->string('title', 200);
            $table->text('content');
            $table->foreignId('user_id')->constrained();
            $table->boolean('published')->default(false);
            $table->timestamps();

            $table->index(['published', 'created_at']);
        });

        // Add more columns to posts
        $this->schema->table('posts', static function (Blueprint $table) {
            $table->string('slug', 250)->unique();
            $table->integer('views')->unsigned()->default(0);
        });

        // Verify everything was created
        static::assertTrue($this->schema->hasTable('users'));
        static::assertTrue($this->schema->hasTable('posts'));
        static::assertTrue($this->schema->hasColumn('posts', 'slug'));
        static::assertTrue($this->schema->hasColumn('posts', 'views'));
        static::assertTrue($this->schema->hasIndex('posts', ['slug']));
    }

    public function testSchemaBuilderWithDifferentColumnTypes(): void
    {
        $this->schema->create('all_types', static function (Blueprint $table) {
            // Numeric
            $table->tinyInteger('tiny');
            $table->smallInteger('small');
            $table->mediumInteger('medium');
            $table->integer('normal');
            $table->bigInteger('big');

            // Decimal
            $table->decimal('price', 10, 2);
            $table->float('rating');
            $table->double('score');

            // String
            $table->char('code', 10);
            $table->string('name', 100);
            $table->text('description');

            // Date/Time
            $table->date('birth_date');
            $table->dateTime('event_at');
            $table->time('alarm_time');
            $table->timestamp('created_at');

            // Special
            $table->boolean('active');
            $table->json('metadata');
            $table->binary('file_data');
            $table->uuid('uuid');
        });

        static::assertTrue($this->schema->hasTable('all_types'));

        $columns = $this->schema->getColumnListing('all_types');
        static::assertGreaterThanOrEqual(19, count($columns));
    }
}
