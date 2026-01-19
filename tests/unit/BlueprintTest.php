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
}
