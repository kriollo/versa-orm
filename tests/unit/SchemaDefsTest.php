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
        self::assertSame('bar', $alter->foo);
        self::assertNull($alter->non_existent);

        // __set
        $alter->new_key = 'new_value';
        self::assertSame('new_value', $alter->new_key);

        // __isset
        self::assertTrue(isset($alter->foo));
        self::assertFalse(isset($alter->missing));
    }

    public function test_alter_changes_offset_methods(): void
    {
        $alter = new AlterChanges(['a' => 1]);

        // offsetGet
        self::assertSame(1, $alter->offsetGet('a'));
        self::assertNull($alter->offsetGet('b'));

        // offsetSet
        $alter->offsetSet('b', 2);
        self::assertSame(2, $alter->b);

        // offsetExists
        self::assertTrue($alter->offsetExists('b'));
        self::assertFalse($alter->offsetExists('c'));

        // offsetUnset
        $alter->offsetUnset('a');
        self::assertFalse(isset($alter->a));
    }

    public function test_column_def_magic_methods(): void
    {
        $col = new ColumnDef(['name' => 'email', 'type' => 'VARCHAR']);

        self::assertSame('email', $col->name);
        self::assertSame('VARCHAR', $col->type);

        $col->nullable = true;
        self::assertTrue($col->nullable);

        self::assertTrue(isset($col->name));
        self::assertFalse(isset($col->default));
    }

    public function test_index_def_all_methods(): void
    {
        $idx = new IndexDef(['name' => 'idx_user', 'columns' => ['user_id']]);

        // Magic
        self::assertSame('idx_user', $idx->name);
        $idx->unique = true;
        self::assertTrue($idx->unique);
        self::assertTrue(isset($idx->name));

        // Offset
        self::assertSame('idx_user', $idx->offsetGet('name'));
        $idx->offsetSet('type', 'BTREE');
        self::assertSame('BTREE', $idx->type);
        self::assertTrue($idx->offsetExists('type'));
        $idx->offsetUnset('unique');
        self::assertFalse(isset($idx->unique));
    }
}
