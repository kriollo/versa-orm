<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\Blueprint;
use VersaORM\Schema\ColumnDefinition;

/**
 * Tests para la clase ColumnDefinition del Schema.
 */
class ColumnDefinitionTest extends TestCase
{
    /**
     * Prueba constructor y métodos básicos.
     */
    public function testConstructorAndGetters(): void
    {
        $column = new ColumnDefinition('name', 'varchar');

        $this->assertEquals('name', $column->getName());
        $this->assertEquals('varchar', $column->getType());
    }

    /**
     * Prueba constructor con Blueprint.
     */
    public function testConstructorWithBlueprint(): void
    {
        $blueprint = new Blueprint('users');
        $column = new ColumnDefinition('email', 'varchar', $blueprint);

        $this->assertEquals('email', $column->getName());
        $this->assertEquals('varchar', $column->getType());
    }

    /**
     * Prueba nullable().
     */
    public function testNullable(): void
    {
        $column = new ColumnDefinition('bio', 'text');
        $result = $column->nullable();

        $this->assertSame($column, $result); // Fluent interface
        $this->assertTrue($column->getAttribute('nullable'));
    }

    /**
     * Prueba nullable(false).
     */
    public function testNotNullable(): void
    {
        $column = new ColumnDefinition('name', 'varchar');
        $column->nullable(false);

        $this->assertFalse($column->getAttribute('nullable'));
    }

    /**
     * Prueba default().
     */
    public function testDefault(): void
    {
        $column = new ColumnDefinition('active', 'boolean');
        $result = $column->default(true);

        $this->assertSame($column, $result);
        $this->assertTrue($column->getAttribute('default'));
    }

    /**
     * Prueba default() con string.
     */
    public function testDefaultString(): void
    {
        $column = new ColumnDefinition('status', 'varchar');
        $column->default('pending');

        $this->assertEquals('pending', $column->getAttribute('default'));
    }

    /**
     * Prueba default() con null.
     */
    public function testDefaultNull(): void
    {
        $column = new ColumnDefinition('description', 'text');
        $column->default(null);

        $this->assertNull($column->getAttribute('default'));
    }

    /**
     * Prueba unsigned().
     */
    public function testUnsigned(): void
    {
        $column = new ColumnDefinition('quantity', 'integer');
        $result = $column->unsigned();

        $this->assertSame($column, $result);
        $this->assertTrue($column->getAttribute('unsigned'));
    }

    /**
     * Prueba autoIncrement().
     */
    public function testAutoIncrement(): void
    {
        $column = new ColumnDefinition('id', 'integer');
        $result = $column->autoIncrement();

        $this->assertSame($column, $result);
        $this->assertTrue($column->getAttribute('autoIncrement'));
    }

    /**
     * Prueba primary().
     */
    public function testPrimary(): void
    {
        $column = new ColumnDefinition('id', 'integer');
        $result = $column->primary();

        $this->assertSame($column, $result);
        $this->assertTrue($column->getAttribute('primary'));
    }

    /**
     * Prueba unique() con Blueprint.
     */
    public function testUnique(): void
    {
        $blueprint = new Blueprint('users');
        $column = new ColumnDefinition('email', 'varchar', $blueprint);
        $result = $column->unique();

        $this->assertSame($column, $result);
        // unique() agrega un índice al blueprint, no al atributo
        $indexes = $blueprint->getIndexes();
        $this->assertCount(1, $indexes);
    }

    /**
     * Prueba index() con Blueprint.
     */
    public function testIndex(): void
    {
        $blueprint = new Blueprint('users');
        $column = new ColumnDefinition('username', 'varchar', $blueprint);
        $result = $column->index();

        $this->assertSame($column, $result);
        // index() agrega un índice al blueprint
        $indexes = $blueprint->getIndexes();
        $this->assertCount(1, $indexes);
    }

    /**
     * Prueba comment().
     */
    public function testComment(): void
    {
        $column = new ColumnDefinition('status', 'varchar');
        $result = $column->comment('User account status');

        $this->assertSame($column, $result);
        $this->assertEquals('User account status', $column->getAttribute('comment'));
    }

    /**
     * Prueba setAttribute() y getAttribute().
     */
    public function testSetAndGetAttribute(): void
    {
        $column = new ColumnDefinition('price', 'decimal');
        $column->setAttribute('precision', 10);
        $column->setAttribute('scale', 2);

        $this->assertEquals(10, $column->getAttribute('precision'));
        $this->assertEquals(2, $column->getAttribute('scale'));
    }

    /**
     * Prueba getAttribute() con valor por defecto.
     */
    public function testGetAttributeWithDefault(): void
    {
        $column = new ColumnDefinition('name', 'varchar');

        $value = $column->getAttribute('nonexistent', 'default_value');
        $this->assertEquals('default_value', $value);
    }

    /**
     * Prueba getAttributes() devuelve todos los atributos.
     */
    public function testGetAttributes(): void
    {
        $column = new ColumnDefinition('created_at', 'timestamp');
        $column->nullable();
        $column->default('CURRENT_TIMESTAMP');

        $attributes = $column->getAttributes();
        $this->assertIsArray($attributes);
        $this->assertArrayHasKey('nullable', $attributes);
        $this->assertArrayHasKey('default', $attributes);
    }

    /**
     * Prueba getModifiers() inicialmente vacío.
     */
    public function testGetModifiersEmpty(): void
    {
        $column = new ColumnDefinition('name', 'varchar');

        $modifiers = $column->getModifiers();
        $this->assertIsArray($modifiers);
        $this->assertCount(0, $modifiers);
    }

    /**
     * Prueba encadenamiento fluido.
     */
    public function testFluentChaining(): void
    {
        $column = new ColumnDefinition('email', 'varchar');

        $result = $column->nullable(false)->default('user@example.com')->comment('User email address');

        $this->assertSame($column, $result);
        $this->assertFalse($column->getAttribute('nullable'));
        $this->assertEquals('user@example.com', $column->getAttribute('default'));
        $this->assertEquals('User email address', $column->getAttribute('comment'));
    }

    /**
     * Prueba combinación de modificadores.
     */
    public function testMultipleModifiers(): void
    {
        $column = new ColumnDefinition('id', 'bigint');
        $column->unsigned()->autoIncrement()->primary();

        $this->assertTrue($column->getAttribute('unsigned'));
        $this->assertTrue($column->getAttribute('autoIncrement'));
        $this->assertTrue($column->getAttribute('primary'));
    }

    /**
     * Prueba after() para posicionamiento.
     */
    public function testAfter(): void
    {
        $column = new ColumnDefinition('middle_name', 'varchar');
        $result = $column->after('first_name');

        $this->assertSame($column, $result);
        $this->assertEquals('first_name', $column->getAttribute('after'));
    }

    /**
     * Prueba first() para posicionamiento.
     */
    public function testFirst(): void
    {
        $column = new ColumnDefinition('priority', 'integer');
        $result = $column->first();

        $this->assertSame($column, $result);
        $this->assertTrue($column->getAttribute('first'));
    }

    /**
     * Prueba storedAs() para columnas generadas.
     */
    public function testStoredAs(): void
    {
        $column = new ColumnDefinition('full_name', 'varchar');
        $result = $column->storedAs('CONCAT(first_name, " ", last_name)');

        $this->assertSame($column, $result);
        $this->assertEquals('CONCAT(first_name, " ", last_name)', $column->getAttribute('storedAs'));
    }
}
