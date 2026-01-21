<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\Dialects\MySQLDialect;

/**
 * Test completo para MySQLDialect
 *
 * @group mysql
 * @group dialects
 */
final class MySQLDialectTest extends TestCase
{
    private MySQLDialect $dialect;

    protected function setUp(): void
    {
        $this->dialect = new MySQLDialect();
    }

    public function test_quote_identifier_asterisk(): void
    {
        static::assertSame('*', $this->dialect->quoteIdentifier('*'));
    }

    public function test_quote_identifier_simple_column(): void
    {
        static::assertSame('`col`', $this->dialect->quoteIdentifier('col'));
        static::assertSame('`user_id`', $this->dialect->quoteIdentifier('user_id'));
        static::assertSame('`name`', $this->dialect->quoteIdentifier('name'));
    }

    public function test_quote_identifier_with_table_prefix(): void
    {
        // MySQLDialect solo maneja table.* especialmente, table.column se escapa completo
        static::assertSame('`users.id`', $this->dialect->quoteIdentifier('users.id'));
        static::assertSame('`posts.title`', $this->dialect->quoteIdentifier('posts.title'));
    }

    public function test_quote_identifier_with_table_asterisk(): void
    {
        static::assertSame('`users`.*', $this->dialect->quoteIdentifier('users.*'));
        static::assertSame('`posts`.*', $this->dialect->quoteIdentifier('posts.*'));
        static::assertSame('`t`.*', $this->dialect->quoteIdentifier('t.*'));
    }

    public function test_quote_identifier_escapes_backticks(): void
    {
        static::assertSame('`my``table`', $this->dialect->quoteIdentifier('my`table'));
        static::assertSame('`col``name`', $this->dialect->quoteIdentifier('col`name'));
    }

    public function test_placeholder_always_returns_question_mark(): void
    {
        static::assertSame('?', $this->dialect->placeholder(0));
        static::assertSame('?', $this->dialect->placeholder(1));
        static::assertSame('?', $this->dialect->placeholder(10));
        static::assertSame('?', $this->dialect->placeholder(999));
    }

    public function test_compile_limit_offset_with_null_values(): void
    {
        static::assertSame('', $this->dialect->compileLimitOffset(null, null));
    }

    public function test_compile_limit_offset_with_limit_only(): void
    {
        static::assertSame(' LIMIT 10', $this->dialect->compileLimitOffset(10, null));
        static::assertSame(' LIMIT 1', $this->dialect->compileLimitOffset(1, null));
        static::assertSame(' LIMIT 100', $this->dialect->compileLimitOffset(100, null));
    }

    public function test_compile_limit_offset_with_offset_only(): void
    {
        static::assertSame(' OFFSET 5', $this->dialect->compileLimitOffset(null, 5));
        static::assertSame(' OFFSET 10', $this->dialect->compileLimitOffset(null, 10));
    }

    public function test_compile_limit_offset_with_both(): void
    {
        static::assertSame(' LIMIT 10 OFFSET 5', $this->dialect->compileLimitOffset(10, 5));
        static::assertSame(' LIMIT 20 OFFSET 100', $this->dialect->compileLimitOffset(20, 100));
        static::assertSame(' LIMIT 1 OFFSET 0', $this->dialect->compileLimitOffset(1, 0));
    }

    public function test_get_name_returns_mysql(): void
    {
        static::assertSame('mysql', $this->dialect->getName());
    }

    public function test_quote_identifier_empty_string(): void
    {
        static::assertSame('``', $this->dialect->quoteIdentifier(''));
    }

    public function test_compile_limit_offset_zero_values(): void
    {
        static::assertSame(' LIMIT 0', $this->dialect->compileLimitOffset(0, null));
        static::assertSame(' OFFSET 0', $this->dialect->compileLimitOffset(null, 0));
        static::assertSame(' LIMIT 0 OFFSET 0', $this->dialect->compileLimitOffset(0, 0));
    }

    public function test_quote_identifier_special_characters(): void
    {
        static::assertSame('`user-name`', $this->dialect->quoteIdentifier('user-name'));
        static::assertSame('`user name`', $this->dialect->quoteIdentifier('user name'));
        static::assertSame('`user@email`', $this->dialect->quoteIdentifier('user@email'));
    }
}
