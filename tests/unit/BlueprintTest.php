<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\Blueprint;
use VersaORM\Schema\ColumnDefinition;

/**
 * Tests para la clase Blueprint del Schema.
 */
class BlueprintTest extends TestCase
{
    /**
     * Prueba constructor y getTable.
     */
    public function testConstructorAndGetTable(): void
    {
        $blueprint = new Blueprint('users');

        static::assertSame('users', $blueprint->getTable());
    }

    /**
     * Prueba id() crea columna auto-incrementing.
     */
    public function testIdColumn(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->id();

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('id', $columns[0]->getName());
    }

    /**
     * Prueba id() con nombre personalizado.
     */
    public function testIdColumnCustomName(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->id('user_id');

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('user_id', $columns[0]->getName());
    }

    /**
     * Prueba string() crea columna VARCHAR.
     */
    public function testStringColumn(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->string('name');

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('name', $columns[0]->getName());
    }

    /**
     * Prueba string() con longitud personalizada.
     */
    public function testStringColumnWithLength(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->string('email', 100);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('email', $columns[0]->getName());
    }

    /**
     * Prueba integer() crea columna INTEGER.
     */
    public function testIntegerColumn(): void
    {
        $blueprint = new Blueprint('products');
        $column = $blueprint->integer('stock');

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('stock', $columns[0]->getName());
    }

    /**
     * Prueba boolean() crea columna BOOLEAN.
     */
    public function testBooleanColumn(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->boolean('active');

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('active', $columns[0]->getName());
    }

    /**
     * Prueba text() crea columna TEXT.
     */
    public function testTextColumn(): void
    {
        $blueprint = new Blueprint('posts');
        $column = $blueprint->text('content');

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('content', $columns[0]->getName());
    }

    /**
     * Prueba timestamp() crea columna TIMESTAMP.
     */
    public function testTimestampColumn(): void
    {
        $blueprint = new Blueprint('posts');
        $column = $blueprint->timestamp('created_at');

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('created_at', $columns[0]->getName());
    }

    /**
     * Prueba timestamps() crea created_at y updated_at.
     */
    public function testTimestampsColumns(): void
    {
        $blueprint = new Blueprint('posts');
        $blueprint->timestamps();

        $columns = $blueprint->getColumns();
        static::assertCount(2, $columns);
        static::assertSame('created_at', $columns[0]->getName());
        static::assertSame('updated_at', $columns[1]->getName());
    }

    /**
     * Prueba múltiples columnas.
     */
    public function testMultipleColumns(): void
    {
        $blueprint = new Blueprint('users');
        $blueprint->id();
        $blueprint->string('name');
        $blueprint->string('email');
        $blueprint->boolean('active');

        $columns = $blueprint->getColumns();
        static::assertCount(4, $columns);
    }

    /**
     * Prueba getIndexes inicialmente vacío.
     */
    public function testGetIndexesEmpty(): void
    {
        $blueprint = new Blueprint('users');

        $indexes = $blueprint->getIndexes();
        static::assertIsArray($indexes);
        static::assertCount(0, $indexes);
    }

    /**
     * Prueba getForeignKeys inicialmente vacío.
     */
    public function testGetForeignKeysEmpty(): void
    {
        $blueprint = new Blueprint('users');

        $foreignKeys = $blueprint->getForeignKeys();
        static::assertIsArray($foreignKeys);
        static::assertCount(0, $foreignKeys);
    }

    /**
     * Prueba getCommands inicialmente vacío.
     */
    public function testGetCommandsEmpty(): void
    {
        $blueprint = new Blueprint('users');

        $commands = $blueprint->getCommands();
        static::assertIsArray($commands);
        static::assertCount(0, $commands);
    }

    /**
     * Prueba float() crea columna FLOAT.
     */
    public function testFloatColumn(): void
    {
        $blueprint = new Blueprint('products');
        $column = $blueprint->float('price');

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('price', $columns[0]->getName());
    }

    /**
     * Prueba decimal() crea columna DECIMAL.
     */
    public function testDecimalColumn(): void
    {
        $blueprint = new Blueprint('products');
        $column = $blueprint->decimal('price', 10, 2);

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('price', $columns[0]->getName());
    }

    /**
     * Prueba date() crea columna DATE.
     */
    public function testDateColumn(): void
    {
        $blueprint = new Blueprint('events');
        $column = $blueprint->date('event_date');

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('event_date', $columns[0]->getName());
    }

    /**
     * Prueba json() crea columna JSON.
     */
    public function testJsonColumn(): void
    {
        $blueprint = new Blueprint('settings');
        $column = $blueprint->json('config');

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('config', $columns[0]->getName());
    }

    /**
     * Prueba enum() crea columna ENUM.
     */
    public function testEnumColumn(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->enum('status', ['active', 'inactive', 'pending']);

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('status', $columns[0]->getName());
    }

    /**
     * Prueba bigInteger() crea columna BIGINT.
     */
    public function testBigIntegerColumn(): void
    {
        $blueprint = new Blueprint('analytics');
        $column = $blueprint->bigInteger('views');

        static::assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        static::assertCount(1, $columns);
        static::assertSame('views', $columns[0]->getName());
    }

    // ==================== TESTS ADICIONALES PARA COVERAGE COMPLETO ====================

    public function testIncrementsColumnType(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->increments('id');
        static::assertSame('increments', $blueprint->getColumns()[0]->getType());
    }

    public function testBigIncrementsColumnType(): void
    {
        $blueprint = new Blueprint('users');
        $blueprint->bigIncrements('id');
        static::assertSame('bigIncrements', $blueprint->getColumns()[0]->getType());
    }

    public function testMediumTextColumnType(): void
    {
        $blueprint = new Blueprint('posts');
        $blueprint->mediumText('content');
        static::assertSame('mediumText', $blueprint->getColumns()[0]->getType());
    }

    public function testLongTextColumnType(): void
    {
        $blueprint = new Blueprint('posts');
        $blueprint->longText('body');
        static::assertSame('longText', $blueprint->getColumns()[0]->getType());
    }

    public function testMediumIntegerColumnType(): void
    {
        $blueprint = new Blueprint('stats');
        $blueprint->mediumInteger('count');
        static::assertSame('mediumInteger', $blueprint->getColumns()[0]->getType());
    }

    public function testSmallIntegerColumnType(): void
    {
        $blueprint = new Blueprint('config');
        $blueprint->smallInteger('value');
        static::assertSame('smallInteger', $blueprint->getColumns()[0]->getType());
    }

    public function testTinyIntegerColumnType(): void
    {
        $blueprint = new Blueprint('flags');
        $blueprint->tinyInteger('status');
        static::assertSame('tinyInteger', $blueprint->getColumns()[0]->getType());
    }

    public function testUnsignedIntegerColumnType(): void
    {
        $blueprint = new Blueprint('products');
        $blueprint->unsignedInteger('quantity');
        static::assertSame('unsignedInteger', $blueprint->getColumns()[0]->getType());
    }

    public function testUnsignedBigIntegerColumnType(): void
    {
        $blueprint = new Blueprint('metrics');
        $blueprint->unsignedBigInteger('counter');
        static::assertSame('unsignedBigInteger', $blueprint->getColumns()[0]->getType());
    }

    public function testFloatColumnWithCustomPrecision(): void
    {
        $blueprint = new Blueprint('measurements');
        $blueprint->float('value', 10, 4);
        static::assertSame('float', $blueprint->getColumns()[0]->getType());
    }

    public function testDoubleColumnWithCustomPrecision(): void
    {
        $blueprint = new Blueprint('coordinates');
        $blueprint->double('latitude', 15, 10);
        static::assertSame('double', $blueprint->getColumns()[0]->getType());
    }

    public function testSetColumnType(): void
    {
        $blueprint = new Blueprint('permissions');
        $blueprint->set('flags', ['read', 'write', 'execute']);
        static::assertSame('set', $blueprint->getColumns()[0]->getType());
    }

    public function testDateColumnCreation(): void
    {
        $blueprint = new Blueprint('events');
        $blueprint->date('event_date');
        static::assertSame('date', $blueprint->getColumns()[0]->getType());
    }

    public function testDateTimeColumnCreation(): void
    {
        $blueprint = new Blueprint('logs');
        $blueprint->dateTime('logged_at');
        static::assertSame('dateTime', $blueprint->getColumns()[0]->getType());
    }

    public function testTimeColumnCreation(): void
    {
        $blueprint = new Blueprint('schedule');
        $blueprint->time('start_time');
        static::assertSame('time', $blueprint->getColumns()[0]->getType());
    }

    public function testTimestampColumnCreation(): void
    {
        $blueprint = new Blueprint('audit');
        $blueprint->timestamp('created_at');
        static::assertSame('timestamp', $blueprint->getColumns()[0]->getType());
    }

    public function testBinaryColumnType(): void
    {
        $blueprint = new Blueprint('files');
        $blueprint->binary('data');
        static::assertSame('binary', $blueprint->getColumns()[0]->getType());
    }

    public function testUuidColumnType(): void
    {
        $blueprint = new Blueprint('users');
        $blueprint->uuid('uuid');
        static::assertSame('uuid', $blueprint->getColumns()[0]->getType());
    }

    public function testCharColumnType(): void
    {
        $blueprint = new Blueprint('codes');
        $blueprint->char('code', 10);
        static::assertSame('char', $blueprint->getColumns()[0]->getType());
    }

    public function testIpAddressColumnType(): void
    {
        $blueprint = new Blueprint('requests');
        $blueprint->ipAddress('ip');
        static::assertSame('ipAddress', $blueprint->getColumns()[0]->getType());
    }

    public function testMacAddressColumnType(): void
    {
        $blueprint = new Blueprint('devices');
        $blueprint->macAddress('mac');
        static::assertSame('macAddress', $blueprint->getColumns()[0]->getType());
    }

    public function testRememberTokenColumnName(): void
    {
        $blueprint = new Blueprint('users');
        $blueprint->rememberToken();
        static::assertSame('remember_token', $blueprint->getColumns()[0]->getName());
    }

    public function testMorphsColumnsCreation(): void
    {
        $blueprint = new Blueprint('images');
        $blueprint->morphs('imageable');
        static::assertCount(2, $blueprint->getColumns());
        static::assertSame('imageable_id', $blueprint->getColumns()[0]->getName());
    }

    public function testNullableMorphsColumnsCreation(): void
    {
        $blueprint = new Blueprint('comments');
        $blueprint->nullableMorphs('commentable');
        static::assertCount(2, $blueprint->getColumns());
        static::assertTrue($blueprint->getColumns()[0]->getAttribute('nullable'));
    }

    public function testForeignIdColumnType(): void
    {
        $blueprint = new Blueprint('posts');
        $blueprint->foreignId('user_id');
        static::assertSame('unsignedBigInteger', $blueprint->getColumns()[0]->getType());
    }

    public function testForeignIdForAutomaticNaming(): void
    {
        $blueprint = new Blueprint('posts');
        $blueprint->foreignIdFor('App\\Models\\User');
        static::assertSame('user_id', $blueprint->getColumns()[0]->getName());
    }

    public function testChangeCommandCreation(): void
    {
        $blueprint = new Blueprint('users');
        $blueprint->change();
        static::assertSame('change', $blueprint->getCommands()[0]['name']);
    }

    public function testRenameColumnCommandCreation(): void
    {
        $blueprint = new Blueprint('users');
        $blueprint->renameColumn('old_name', 'new_name');
        static::assertSame('renameColumn', $blueprint->getCommands()[0]['name']);
    }

    public function testDropMultipleColumnsCommand(): void
    {
        $blueprint = new Blueprint('users');
        $blueprint->dropColumn(['col1', 'col2', 'col3']);
        static::assertCount(3, $blueprint->getCommands()[0]['columns']);
    }

    public function testFullTextIndexCreation(): void
    {
        $blueprint = new Blueprint('articles');
        $blueprint->fullText(['title', 'body']);
        static::assertSame('fulltext', $blueprint->getIndexes()[0]['type']);
    }

    public function testSpatialIndexCreation(): void
    {
        $blueprint = new Blueprint('locations');
        $blueprint->spatialIndex('coordinates');
        static::assertSame('spatial', $blueprint->getIndexes()[0]['type']);
    }

    public function testDropPrimaryCommandCreation(): void
    {
        $blueprint = new Blueprint('users');
        $blueprint->dropPrimary();
        static::assertSame('dropPrimary', $blueprint->getCommands()[0]['name']);
    }
}
