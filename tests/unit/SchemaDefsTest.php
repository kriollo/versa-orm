<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\AlterChanges;
use VersaORM\ColumnDef;
use VersaORM\IndexDef;

/**
 * @group core
 */
class SchemaDefsTest extends TestCase
{
    public function test_alter_changes_magic_methods(): void
    {
        $alter = new AlterChanges(['foo' => 'bar']);

        // __get
        static::assertSame('bar', $alter->foo);
        static::assertNull($alter->non_existent);

        // __set
        $alter->new_key = 'new_value';
        static::assertSame('new_value', $alter->new_key);

        // __isset
        static::assertTrue(isset($alter->foo));
        static::assertFalse(isset($alter->missing));
    }

    public function test_alter_changes_offset_methods(): void
    {
        $alter = new AlterChanges(['a' => 1]);

        // offsetGet
        static::assertSame(1, $alter->offsetGet('a'));
        static::assertNull($alter->offsetGet('b'));

        // offsetSet
        $alter->offsetSet('b', 2);
        static::assertSame(2, $alter->b);

        // offsetExists
        static::assertTrue($alter->offsetExists('b'));
        static::assertFalse($alter->offsetExists('c'));

        // offsetUnset
        $alter->offsetUnset('a');
        static::assertFalse(isset($alter->a));
    }

    public function test_column_def_magic_methods(): void
    {
        $col = new ColumnDef(['name' => 'email', 'type' => 'VARCHAR']);

        static::assertSame('email', $col->name);
        static::assertSame('VARCHAR', $col->type);

        $col->nullable = true;
        static::assertTrue($col->nullable);

        static::assertTrue(isset($col->name));
        static::assertFalse(isset($col->default));
    }

    public function test_index_def_all_methods(): void
    {
        $idx = new IndexDef(['name' => 'idx_user', 'columns' => ['user_id']]);

        // Magic
        static::assertSame('idx_user', $idx->name);
        $idx->unique = true;
        static::assertTrue($idx->unique);
        static::assertTrue(isset($idx->name));

        // Offset
        static::assertSame('idx_user', $idx->offsetGet('name'));
        $idx->offsetSet('type', 'BTREE');
        static::assertSame('BTREE', $idx->type);
        static::assertTrue($idx->offsetExists('type'));
        $idx->offsetUnset('unique');
        static::assertFalse(isset($idx->unique));
    }
}
