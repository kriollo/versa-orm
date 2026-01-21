<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\Blueprint;
use VersaORM\Schema\SchemaBuilder;
use VersaORM\VersaORM;

/**
 * Tests de integración rápidos para SchemaBuilder con SQLite in-memory.
 */
class SchemaBuilderIntegrationTest extends TestCase
{
    private VersaORM $orm;
    private SchemaBuilder $schema;

    protected function setUp(): void
    {
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]);

        $this->schema = new SchemaBuilder($this->orm);
    }

    public function testCreateTableWithAllColumnTypes(): void
    {
        $this->schema->create('test_all_types', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->text('description');
            $table->integer('quantity');
            $table->bigInteger('big_num');
            $table->decimal('price', 10, 2);
            $table->float('rating');
            $table->double('score');
            $table->boolean('active');
            $table->date('birth_date');
            $table->dateTime('event_at');
            $table->time('alarm_time');
            $table->timestamp('created_at');
            $table->json('metadata');
            $table->binary('file_data');
        });

        static::assertTrue($this->schema->hasTable('test_all_types'));

        $columns = $this->schema->getColumnListing('test_all_types');
        static::assertContains('name', $columns);
        static::assertContains('description', $columns);
        static::assertContains('quantity', $columns);
        static::assertContains('price', $columns);
        static::assertContains('active', $columns);
        static::assertContains('metadata', $columns);
    }

    public function testCreateTableWithConstraints(): void
    {
        $this->schema->create('test_constraints', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100)->unique();
            $table->string('username', 50)->index();
            $table->integer('age')->unsigned()->nullable();
            $table->string('status', 20)->default('active');
            $table->text('bio')->nullable();
            $table->timestamp('created_at')->useCurrent();
        });

        static::assertTrue($this->schema->hasTable('test_constraints'));
        static::assertTrue($this->schema->hasColumn('test_constraints', 'email'));
        static::assertTrue($this->schema->hasColumn('test_constraints', 'username'));
        static::assertTrue($this->schema->hasIndex('test_constraints', ['email']));
        static::assertTrue($this->schema->hasIndex('test_constraints', ['username']));
    }

    public function testCreateTableWithForeignKeys(): void
    {
        $this->schema->create('users', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
        });

        $this->schema->create('posts', static function (Blueprint $table) {
            $table->id();
            $table->string('title', 200);
            $table->foreignId('user_id')->constrained();
        });

        static::assertTrue($this->schema->hasTable('posts'));
        static::assertTrue($this->schema->hasColumn('posts', 'user_id'));

        $foreignKeys = $this->schema->getForeignKeys('posts');
        static::assertNotEmpty($foreignKeys);
    }

    public function testCreateTableWithCompositeIndexes(): void
    {
        $this->schema->create('products', static function (Blueprint $table) {
            $table->id();
            $table->string('sku', 50);
            $table->string('category', 50);
            $table->string('brand', 50);
            $table->index(['category', 'brand'], 'idx_category_brand');
            $table->unique(['sku', 'category'], 'unique_sku_category');
        });

        static::assertTrue($this->schema->hasTable('products'));
        static::assertTrue($this->schema->hasIndex('products', ['category', 'brand']));
        static::assertTrue($this->schema->hasIndex('products', ['sku', 'category']));
    }

    public function testAlterTableAddMultipleColumns(): void
    {
        $this->schema->create('orders', static function (Blueprint $table) {
            $table->id();
            $table->string('order_number', 50);
        });

        $this->schema->table('orders', static function (Blueprint $table) {
            $table->decimal('total', 10, 2);
            $table->string('status', 20)->default('pending');
            $table->timestamp('completed_at')->nullable();
            $table->text('notes')->nullable();
        });

        static::assertTrue($this->schema->hasColumn('orders', 'total'));
        static::assertTrue($this->schema->hasColumn('orders', 'status'));
        static::assertTrue($this->schema->hasColumn('orders', 'completed_at'));
        static::assertTrue($this->schema->hasColumn('orders', 'notes'));
    }

    public function testAlterTableAddIndexes(): void
    {
        $this->schema->create('customers', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100);
            $table->string('phone', 20);
            $table->string('city', 50);
        });

        $this->schema->table('customers', static function (Blueprint $table) {
            $table->index('email');
            $table->index('phone');
            $table->index(['city', 'email'], 'idx_city_email');
        });

        static::assertTrue($this->schema->hasIndex('customers', ['email']));
        static::assertTrue($this->schema->hasIndex('customers', ['phone']));
        static::assertTrue($this->schema->hasIndex('customers', ['city', 'email']));
    }

    public function testDropColumn(): void
    {
        $this->schema->create('test_drop', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->string('temp_field', 50);
            $table->integer('age');
        });

        static::assertTrue($this->schema->hasColumn('test_drop', 'temp_field'));

        $this->schema->table('test_drop', static function (Blueprint $table) {
            $table->dropColumn('temp_field');
        });

        static::assertFalse($this->schema->hasColumn('test_drop', 'temp_field'));
        static::assertTrue($this->schema->hasColumn('test_drop', 'name'));
        static::assertTrue($this->schema->hasColumn('test_drop', 'age'));
    }

    public function testDropMultipleColumns(): void
    {
        $this->schema->create('test_drop_many', static function (Blueprint $table) {
            $table->id();
            $table->string('field1', 50);
            $table->string('field2', 50);
            $table->string('field3', 50);
            $table->string('keep_me', 50);
        });

        $this->schema->table('test_drop_many', static function (Blueprint $table) {
            $table->dropColumn(['field1', 'field2', 'field3']);
        });

        static::assertFalse($this->schema->hasColumn('test_drop_many', 'field1'));
        static::assertFalse($this->schema->hasColumn('test_drop_many', 'field2'));
        static::assertFalse($this->schema->hasColumn('test_drop_many', 'field3'));
        static::assertTrue($this->schema->hasColumn('test_drop_many', 'keep_me'));
    }

    public function testRenameColumn(): void
    {
        static::markTestSkipped('SQLite does not support renaming columns directly');

        $this->schema->create('test_rename', static function (Blueprint $table) {
            $table->id();
            $table->string('old_name', 100);
            $table->string('other_field', 50);
        });

        $this->schema->table('test_rename', static function (Blueprint $table) {
            $table->renameColumn('old_name', 'new_name');
        });

        static::assertFalse($this->schema->hasColumn('test_rename', 'old_name'));
        static::assertTrue($this->schema->hasColumn('test_rename', 'new_name'));
        static::assertTrue($this->schema->hasColumn('test_rename', 'other_field'));
    }

    public function testModifyColumn(): void
    {
        static::markTestSkipped('SQLite does not support altering columns directly');

        $this->schema->create('test_modify', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 50);
        });

        $this->schema->table('test_modify', static function (Blueprint $table) {
            $table->string('name', 200)->change();
        });

        $columns = $this->schema->getColumns('test_modify');
        static::assertNotEmpty($columns);

        $nameColumn = array_filter($columns, static fn($col) => $col['name'] === 'name');
        static::assertNotEmpty($nameColumn);
    }

    public function testRenameTable(): void
    {
        $this->schema->create('old_table_name', static function (Blueprint $table) {
            $table->id();
            $table->string('data', 100);
        });

        static::assertTrue($this->schema->hasTable('old_table_name'));

        $this->schema->rename('old_table_name', 'new_table_name');

        static::assertFalse($this->schema->hasTable('old_table_name'));
        static::assertTrue($this->schema->hasTable('new_table_name'));
    }

    public function testDropTable(): void
    {
        $this->schema->create('drop_me', static function (Blueprint $table) {
            $table->id();
            $table->string('data', 100);
        });

        static::assertTrue($this->schema->hasTable('drop_me'));

        $this->schema->drop('drop_me');

        static::assertFalse($this->schema->hasTable('drop_me'));
    }

    public function testDropIfExists(): void
    {
        $this->schema->dropIfExists('non_existent_table');

        $this->schema->create('exists_table', static function (Blueprint $table) {
            $table->id();
        });

        static::assertTrue($this->schema->hasTable('exists_table'));

        $this->schema->dropIfExists('exists_table');

        static::assertFalse($this->schema->hasTable('exists_table'));
    }

    public function testGetColumnListing(): void
    {
        $this->schema->create('list_test', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->string('email', 100);
            $table->integer('age');
            $table->timestamp('created_at');
        });

        $columns = $this->schema->getColumnListing('list_test');

        static::assertIsArray($columns);
        static::assertContains('id', $columns);
        static::assertContains('name', $columns);
        static::assertContains('email', $columns);
        static::assertContains('age', $columns);
        static::assertContains('created_at', $columns);
    }

    public function testGetColumnsDetailed(): void
    {
        $this->schema->create('detailed_test', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100)->nullable();
            $table->integer('count')->default(0);
            $table->boolean('active')->default(true);
        });

        $columns = $this->schema->getColumns('detailed_test');

        static::assertIsArray($columns);
        static::assertNotEmpty($columns);

        foreach ($columns as $column) {
            static::assertArrayHasKey('name', $column);
            static::assertArrayHasKey('type', $column);
        }
    }

    public function testGetIndexes(): void
    {
        $this->schema->create('index_test', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100)->unique();
            $table->string('username', 50)->index();
            $table->string('name', 100);
        });

        $indexes = $this->schema->getIndexes('index_test');

        static::assertIsArray($indexes);
        static::assertNotEmpty($indexes);
    }

    public function testCreateTableWithTimestamps(): void
    {
        $this->schema->create('timestamp_test', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->timestamps();
        });

        static::assertTrue($this->schema->hasColumn('timestamp_test', 'created_at'));
        static::assertTrue($this->schema->hasColumn('timestamp_test', 'updated_at'));
    }

    public function testCreateTableWithSoftDeletes(): void
    {
        $this->schema->create('soft_delete_test', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->softDeletes();
        });

        static::assertTrue($this->schema->hasColumn('soft_delete_test', 'deleted_at'));
    }

    public function testCreateTableWithRememberToken(): void
    {
        $this->schema->create('auth_test', static function (Blueprint $table) {
            $table->id();
            $table->string('email', 100);
            $table->rememberToken();
        });

        static::assertTrue($this->schema->hasColumn('auth_test', 'remember_token'));
    }

    public function testCreateTableWithUuid(): void
    {
        $this->schema->create('uuid_test', static function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('name', 100);
        });

        static::assertTrue($this->schema->hasColumn('uuid_test', 'id'));
    }

    public function testCreateTableWithMorphs(): void
    {
        $this->schema->create('morph_test', static function (Blueprint $table) {
            $table->id();
            $table->morphs('taggable');
        });

        static::assertTrue($this->schema->hasColumn('morph_test', 'taggable_id'));
        static::assertTrue($this->schema->hasColumn('morph_test', 'taggable_type'));
    }

    public function testCreateTableWithNullableMorphs(): void
    {
        $this->schema->create('nullable_morph_test', static function (Blueprint $table) {
            $table->id();
            $table->nullableMorphs('commentable');
        });

        static::assertTrue($this->schema->hasColumn('nullable_morph_test', 'commentable_id'));
        static::assertTrue($this->schema->hasColumn('nullable_morph_test', 'commentable_type'));
    }

    public function testHasTableReturnsFalseForNonExistent(): void
    {
        static::assertFalse($this->schema->hasTable('definitely_does_not_exist'));
    }

    public function testHasColumnReturnsFalseForNonExistent(): void
    {
        $this->schema->create('column_check', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
        });

        static::assertFalse($this->schema->hasColumn('column_check', 'non_existent_column'));
    }

    public function testHasIndexReturnsFalseForNonExistent(): void
    {
        $this->schema->create('index_check', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
        });

        static::assertFalse($this->schema->hasIndex('index_check', ['non_existent_column']));
    }

    public function testComplexTableWithAllFeatures(): void
    {
        $this->schema->create('categories', static function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
        });

        $this->schema->create('complex_table', static function (Blueprint $table) {
            $table->id();
            $table->string('title', 200)->unique();
            $table->text('content')->nullable();
            $table->string('slug', 250)->index();
            $table->integer('views')->unsigned()->default(0);
            $table->decimal('price', 10, 2)->nullable();
            $table->boolean('published')->default(false);
            $table->json('metadata')->nullable();
            $table->foreignId('category_id')->constrained();
            $table->timestamps();
            $table->softDeletes();

            $table->index(['published', 'created_at'], 'idx_published_date');
        });

        static::assertTrue($this->schema->hasTable('complex_table'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'title'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'content'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'slug'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'views'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'price'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'published'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'metadata'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'category_id'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'created_at'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'updated_at'));
        static::assertTrue($this->schema->hasColumn('complex_table', 'deleted_at'));

        static::assertTrue($this->schema->hasIndex('complex_table', ['title']));
        static::assertTrue($this->schema->hasIndex('complex_table', ['slug']));
        static::assertTrue($this->schema->hasIndex('complex_table', ['published', 'created_at']));
    }
}
