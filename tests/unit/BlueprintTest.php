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

        $this->assertEquals('users', $blueprint->getTable());
    }

    /**
     * Prueba id() crea columna auto-incrementing.
     */
    public function testIdColumn(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->id();

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('id', $columns[0]->getName());
    }

    /**
     * Prueba id() con nombre personalizado.
     */
    public function testIdColumnCustomName(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->id('user_id');

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('user_id', $columns[0]->getName());
    }

    /**
     * Prueba string() crea columna VARCHAR.
     */
    public function testStringColumn(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->string('name');

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('name', $columns[0]->getName());
    }

    /**
     * Prueba string() con longitud personalizada.
     */
    public function testStringColumnWithLength(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->string('email', 100);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('email', $columns[0]->getName());
    }

    /**
     * Prueba integer() crea columna INTEGER.
     */
    public function testIntegerColumn(): void
    {
        $blueprint = new Blueprint('products');
        $column = $blueprint->integer('stock');

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('stock', $columns[0]->getName());
    }

    /**
     * Prueba boolean() crea columna BOOLEAN.
     */
    public function testBooleanColumn(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->boolean('active');

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('active', $columns[0]->getName());
    }

    /**
     * Prueba text() crea columna TEXT.
     */
    public function testTextColumn(): void
    {
        $blueprint = new Blueprint('posts');
        $column = $blueprint->text('content');

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('content', $columns[0]->getName());
    }

    /**
     * Prueba timestamp() crea columna TIMESTAMP.
     */
    public function testTimestampColumn(): void
    {
        $blueprint = new Blueprint('posts');
        $column = $blueprint->timestamp('created_at');

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('created_at', $columns[0]->getName());
    }

    /**
     * Prueba timestamps() crea created_at y updated_at.
     */
    public function testTimestampsColumns(): void
    {
        $blueprint = new Blueprint('posts');
        $blueprint->timestamps();

        $columns = $blueprint->getColumns();
        $this->assertCount(2, $columns);
        $this->assertEquals('created_at', $columns[0]->getName());
        $this->assertEquals('updated_at', $columns[1]->getName());
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
        $this->assertCount(4, $columns);
    }

    /**
     * Prueba getIndexes inicialmente vacío.
     */
    public function testGetIndexesEmpty(): void
    {
        $blueprint = new Blueprint('users');

        $indexes = $blueprint->getIndexes();
        $this->assertIsArray($indexes);
        $this->assertCount(0, $indexes);
    }

    /**
     * Prueba getForeignKeys inicialmente vacío.
     */
    public function testGetForeignKeysEmpty(): void
    {
        $blueprint = new Blueprint('users');

        $foreignKeys = $blueprint->getForeignKeys();
        $this->assertIsArray($foreignKeys);
        $this->assertCount(0, $foreignKeys);
    }

    /**
     * Prueba getCommands inicialmente vacío.
     */
    public function testGetCommandsEmpty(): void
    {
        $blueprint = new Blueprint('users');

        $commands = $blueprint->getCommands();
        $this->assertIsArray($commands);
        $this->assertCount(0, $commands);
    }

    /**
     * Prueba float() crea columna FLOAT.
     */
    public function testFloatColumn(): void
    {
        $blueprint = new Blueprint('products');
        $column = $blueprint->float('price');

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('price', $columns[0]->getName());
    }

    /**
     * Prueba decimal() crea columna DECIMAL.
     */
    public function testDecimalColumn(): void
    {
        $blueprint = new Blueprint('products');
        $column = $blueprint->decimal('price', 10, 2);

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('price', $columns[0]->getName());
    }

    /**
     * Prueba date() crea columna DATE.
     */
    public function testDateColumn(): void
    {
        $blueprint = new Blueprint('events');
        $column = $blueprint->date('event_date');

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('event_date', $columns[0]->getName());
    }

    /**
     * Prueba json() crea columna JSON.
     */
    public function testJsonColumn(): void
    {
        $blueprint = new Blueprint('settings');
        $column = $blueprint->json('config');

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('config', $columns[0]->getName());
    }

    /**
     * Prueba enum() crea columna ENUM.
     */
    public function testEnumColumn(): void
    {
        $blueprint = new Blueprint('users');
        $column = $blueprint->enum('status', ['active', 'inactive', 'pending']);

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('status', $columns[0]->getName());
    }

    /**
     * Prueba bigInteger() crea columna BIGINT.
     */
    public function testBigIntegerColumn(): void
    {
        $blueprint = new Blueprint('analytics');
        $column = $blueprint->bigInteger('views');

        $this->assertInstanceOf(ColumnDefinition::class, $column);

        $columns = $blueprint->getColumns();
        $this->assertCount(1, $columns);
        $this->assertEquals('views', $columns[0]->getName());
    }
}
