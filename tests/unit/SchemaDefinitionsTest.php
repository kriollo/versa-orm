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

        static::assertSame('id', $column->name);
        static::assertSame('INTEGER', $column->type);
        static::assertFalse($column->nullable);
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

        static::assertSame('username', $column->name);
        static::assertSame('VARCHAR', $column->type);
        static::assertSame(255, $column->length);
    }

    /**
     * Prueba __isset de ColumnDef.
     */
    public function testColumnDefMagicIsset(): void
    {
        $column = new ColumnDef(['name' => 'email']);

        static::assertTrue(isset($column->name));
        static::assertFalse(isset($column->nonexistent));
    }

    /**
     * Prueba ColumnDef con array vacío.
     */
    public function testColumnDefEmptyConstructor(): void
    {
        $column = new ColumnDef();

        static::assertNull($column->name);
        static::assertNull($column->type);
    }

    /**
     * Prueba constructor y acceso mágico de IndexDef.
     */
    public function testIndexDefConstructorAndMagicGet(): void
    {
        $index = new IndexDef(['name' => 'idx_email', 'columns' => ['email'], 'unique' => true]);

        static::assertSame('idx_email', $index->name);
        static::assertEquals(['email'], $index->columns);
        static::assertTrue($index->unique);
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

        static::assertSame('idx_username', $index->name);
        static::assertEquals(['username'], $index->columns);
        static::assertFalse($index->unique);
    }

    /**
     * Prueba __isset de IndexDef.
     */
    public function testIndexDefMagicIsset(): void
    {
        $index = new IndexDef(['name' => 'idx_test']);

        static::assertTrue(isset($index->name));
        static::assertFalse(isset($index->columns));
    }

    /**
     * Prueba ArrayAccess offsetGet de IndexDef.
     */
    public function testIndexDefOffsetGet(): void
    {
        $index = new IndexDef(['name' => 'idx_composite', 'columns' => ['first_name', 'last_name']]);

        static::assertSame('idx_composite', $index->offsetGet('name'));
        static::assertEquals(['first_name', 'last_name'], $index->offsetGet('columns'));
    }

    /**
     * Prueba ArrayAccess offsetSet de IndexDef.
     */
    public function testIndexDefOffsetSet(): void
    {
        $index = new IndexDef();
        $index->offsetSet('name', 'idx_new');
        $index->offsetSet('type', 'BTREE');

        static::assertSame('idx_new', $index->offsetGet('name'));
        static::assertSame('BTREE', $index->offsetGet('type'));
    }

    /**
     * Prueba ArrayAccess offsetExists de IndexDef.
     */
    public function testIndexDefOffsetExists(): void
    {
        $index = new IndexDef(['name' => 'idx_test']);

        static::assertTrue($index->offsetExists('name'));
        static::assertFalse($index->offsetExists('columns'));
    }

    /**
     * Prueba ArrayAccess offsetUnset de IndexDef.
     */
    public function testIndexDefOffsetUnset(): void
    {
        $index = new IndexDef(['name' => 'idx_test', 'type' => 'HASH']);
        $index->offsetUnset('type');

        static::assertFalse(isset($index->type));
        static::assertTrue(isset($index->name));
    }

    /**
     * Prueba IndexDef con array vacío.
     */
    public function testIndexDefEmptyConstructor(): void
    {
        $index = new IndexDef();

        static::assertNull($index->name);
        static::assertNull($index->columns);
    }

    /**
     * Prueba constructor y acceso mágico de TableConstraintsDef.
     */
    public function testTableConstraintsDefConstructorAndMagicGet(): void
    {
        $constraints = new TableConstraintsDef(['primaryKey' => 'id', 'foreignKeys' => []]);

        static::assertSame('id', $constraints->primaryKey);
        static::assertEquals([], $constraints->foreignKeys);
    }

    /**
     * Prueba __set de TableConstraintsDef.
     */
    public function testTableConstraintsDefMagicSet(): void
    {
        $constraints = new TableConstraintsDef();
        $constraints->primaryKey = 'user_id';
        $constraints->uniqueKeys = [['email']];

        static::assertSame('user_id', $constraints->primaryKey);
        static::assertEquals([['email']], $constraints->uniqueKeys);
    }

    /**
     * Prueba __isset de TableConstraintsDef.
     */
    public function testTableConstraintsDefMagicIsset(): void
    {
        $constraints = new TableConstraintsDef(['primaryKey' => 'id']);

        static::assertTrue(isset($constraints->primaryKey));
        static::assertFalse(isset($constraints->foreignKeys));
    }

    /**
     * Prueba TableConstraintsDef con array vacío.
     */
    public function testTableConstraintsDefEmptyConstructor(): void
    {
        $constraints = new TableConstraintsDef();

        static::assertNull($constraints->primaryKey);
        static::assertNull($constraints->foreignKeys);
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

        static::assertSame('id', $constraints->primaryKey);
        static::assertCount(1, $constraints->foreignKeys);
        static::assertCount(2, $constraints->uniqueKeys);
        static::assertCount(1, $constraints->checks);
    }
}
