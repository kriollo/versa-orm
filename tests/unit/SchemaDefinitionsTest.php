<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\ColumnDef;
use VersaORM\IndexDef;
use VersaORM\TableConstraintsDef;

/**
 * Tests para clases de definición de esquema.
 */
class SchemaDefinitionsTest extends TestCase
{
    /**
     * Prueba constructor y acceso mágico de ColumnDef.
     */
    public function testColumnDefConstructorAndMagicGet(): void
    {
        $column = new ColumnDef(['name' => 'id', 'type' => 'INTEGER', 'nullable' => false]);

        $this->assertEquals('id', $column->name);
        $this->assertEquals('INTEGER', $column->type);
        $this->assertFalse($column->nullable);
    }

    /**
     * Prueba __set de ColumnDef.
     */
    public function testColumnDefMagicSet(): void
    {
        $column = new ColumnDef();
        $column->name = 'username';
        $column->type = 'VARCHAR';
        $column->length = 255;

        $this->assertEquals('username', $column->name);
        $this->assertEquals('VARCHAR', $column->type);
        $this->assertEquals(255, $column->length);
    }

    /**
     * Prueba __isset de ColumnDef.
     */
    public function testColumnDefMagicIsset(): void
    {
        $column = new ColumnDef(['name' => 'email']);

        $this->assertTrue(isset($column->name));
        $this->assertFalse(isset($column->nonexistent));
    }

    /**
     * Prueba ColumnDef con array vacío.
     */
    public function testColumnDefEmptyConstructor(): void
    {
        $column = new ColumnDef();

        $this->assertNull($column->name);
        $this->assertNull($column->type);
    }

    /**
     * Prueba constructor y acceso mágico de IndexDef.
     */
    public function testIndexDefConstructorAndMagicGet(): void
    {
        $index = new IndexDef(['name' => 'idx_email', 'columns' => ['email'], 'unique' => true]);

        $this->assertEquals('idx_email', $index->name);
        $this->assertEquals(['email'], $index->columns);
        $this->assertTrue($index->unique);
    }

    /**
     * Prueba __set de IndexDef.
     */
    public function testIndexDefMagicSet(): void
    {
        $index = new IndexDef();
        $index->name = 'idx_username';
        $index->columns = ['username'];
        $index->unique = false;

        $this->assertEquals('idx_username', $index->name);
        $this->assertEquals(['username'], $index->columns);
        $this->assertFalse($index->unique);
    }

    /**
     * Prueba __isset de IndexDef.
     */
    public function testIndexDefMagicIsset(): void
    {
        $index = new IndexDef(['name' => 'idx_test']);

        $this->assertTrue(isset($index->name));
        $this->assertFalse(isset($index->columns));
    }

    /**
     * Prueba ArrayAccess offsetGet de IndexDef.
     */
    public function testIndexDefOffsetGet(): void
    {
        $index = new IndexDef(['name' => 'idx_composite', 'columns' => ['first_name', 'last_name']]);

        $this->assertEquals('idx_composite', $index->offsetGet('name'));
        $this->assertEquals(['first_name', 'last_name'], $index->offsetGet('columns'));
    }

    /**
     * Prueba ArrayAccess offsetSet de IndexDef.
     */
    public function testIndexDefOffsetSet(): void
    {
        $index = new IndexDef();
        $index->offsetSet('name', 'idx_new');
        $index->offsetSet('type', 'BTREE');

        $this->assertEquals('idx_new', $index->offsetGet('name'));
        $this->assertEquals('BTREE', $index->offsetGet('type'));
    }

    /**
     * Prueba ArrayAccess offsetExists de IndexDef.
     */
    public function testIndexDefOffsetExists(): void
    {
        $index = new IndexDef(['name' => 'idx_test']);

        $this->assertTrue($index->offsetExists('name'));
        $this->assertFalse($index->offsetExists('columns'));
    }

    /**
     * Prueba ArrayAccess offsetUnset de IndexDef.
     */
    public function testIndexDefOffsetUnset(): void
    {
        $index = new IndexDef(['name' => 'idx_test', 'type' => 'HASH']);
        $index->offsetUnset('type');

        $this->assertFalse(isset($index->type));
        $this->assertTrue(isset($index->name));
    }

    /**
     * Prueba IndexDef con array vacío.
     */
    public function testIndexDefEmptyConstructor(): void
    {
        $index = new IndexDef();

        $this->assertNull($index->name);
        $this->assertNull($index->columns);
    }

    /**
     * Prueba constructor y acceso mágico de TableConstraintsDef.
     */
    public function testTableConstraintsDefConstructorAndMagicGet(): void
    {
        $constraints = new TableConstraintsDef(['primaryKey' => 'id', 'foreignKeys' => []]);

        $this->assertEquals('id', $constraints->primaryKey);
        $this->assertEquals([], $constraints->foreignKeys);
    }

    /**
     * Prueba __set de TableConstraintsDef.
     */
    public function testTableConstraintsDefMagicSet(): void
    {
        $constraints = new TableConstraintsDef();
        $constraints->primaryKey = 'user_id';
        $constraints->uniqueKeys = [['email']];

        $this->assertEquals('user_id', $constraints->primaryKey);
        $this->assertEquals([['email']], $constraints->uniqueKeys);
    }

    /**
     * Prueba __isset de TableConstraintsDef.
     */
    public function testTableConstraintsDefMagicIsset(): void
    {
        $constraints = new TableConstraintsDef(['primaryKey' => 'id']);

        $this->assertTrue(isset($constraints->primaryKey));
        $this->assertFalse(isset($constraints->foreignKeys));
    }

    /**
     * Prueba TableConstraintsDef con array vacío.
     */
    public function testTableConstraintsDefEmptyConstructor(): void
    {
        $constraints = new TableConstraintsDef();

        $this->assertNull($constraints->primaryKey);
        $this->assertNull($constraints->foreignKeys);
    }

    /**
     * Prueba TableConstraintsDef con múltiples restricciones.
     */
    public function testTableConstraintsDefMultipleConstraints(): void
    {
        $constraints = new TableConstraintsDef([
            'primaryKey' => 'id',
            'foreignKeys' => [
                ['column' => 'user_id', 'references' => 'users', 'on' => 'id'],
            ],
            'uniqueKeys' => [['email'], ['username']],
            'checks' => ['age > 0'],
        ]);

        $this->assertEquals('id', $constraints->primaryKey);
        $this->assertCount(1, $constraints->foreignKeys);
        $this->assertCount(2, $constraints->uniqueKeys);
        $this->assertCount(1, $constraints->checks);
    }
}
