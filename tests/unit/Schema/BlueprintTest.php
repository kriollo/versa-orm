<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\Blueprint;
use VersaORM\Schema\ColumnDefinition;

/**
 * @group core
 */
class BlueprintTest extends TestCase
{
    public function test_blueprint_basic_getters(): void
    {
        $bp = new Blueprint('users');
        self::assertSame('users', $bp->getTable());
        self::assertEmpty($bp->getColumns());
        self::assertEmpty($bp->getIndexes());
        self::assertEmpty($bp->getForeignKeys());
        self::assertEmpty($bp->getCommands());
    }

    public function test_blueprint_column_helpers(): void
    {
        $bp = new Blueprint('test_table');

        $bp->id();
        $bp->string('name', 100);
        $bp->text('bio');
        $bp->integer('age');
        $bp->bigInteger('large_id');
        $bp->float('price');
        $bp->decimal('rate', 10, 5);
        $bp->boolean('is_active');
        $bp->json('metadata');
        $bp->date('birthday');
        $bp->dateTime('published_at');
        $bp->timestamp('created_at');
        $bp->timestamps();
        $bp->uuid('guid');
        $bp->enum('choice', ['a', 'b']);
        $bp->ipAddress('ip');
        $bp->rememberToken();
        $bp->morphs('taggable');
        $bp->foreignId('user_id');

        $columns = $bp->getColumns();
        self::assertCount(21, $columns);
    }

    public function test_blueprint_commands_and_indices(): void
    {
        $bp = new Blueprint('posts');
        $bp->index('user_id', 'idx_user');
        $bp->unique(['slug', 'deleted_at']);
        $bp->fullText('content');

        $bp->dropColumn('old_col');
        $bp->renameColumn('title', 'subject');

        self::assertCount(3, $bp->getIndexes());
        self::assertCount(2, $bp->getCommands());
    }

    public function test_column_definition_to_sql(): void
    {
        $bp = new Blueprint('users');
        $col = new ColumnDefinition('name', 'string', $bp);
        $col->length(50)->nullable()->default('John');

        self::assertSame('`name` VARCHAR(50) NULL DEFAULT \'John\'', $col->toSql('mysql'));
        self::assertSame('"name" VARCHAR(50) NULL DEFAULT \'John\'', $col->toSql('postgresql'));
        self::assertSame('"name" TEXT NULL DEFAULT \'John\'', $col->toSql('sqlite'));
    }

    public function test_column_definition_modifiers(): void
    {
        $bp = new Blueprint('users');
        $col = new ColumnDefinition('id', 'id', $bp);
        $col->primary()->autoIncrement();

        $sql = $col->toSql('mysql');
        self::assertStringContainsString('AUTO_INCREMENT', $sql);

        $col2 = new ColumnDefinition('created_at', 'timestamp', $bp);
        $col2->useCurrent();
        self::assertStringContainsString('DEFAULT CURRENT_TIMESTAMP', $col2->toSql('mysql'));

        $col3 = new ColumnDefinition('updated_at', 'timestamp', $bp);
        $col3->useCurrentOnUpdate();
        self::assertStringContainsString('ON UPDATE CURRENT_TIMESTAMP', $col3->toSql('mysql'));
    }

    public function test_foreign_key_definition(): void
    {
        $bp = new Blueprint('posts');
        $col = $bp->foreignId('user_id');
        $foreign = $col->references('id')->on('users')->cascadeOnDelete();

        self::assertSame('user_id', $foreign->getLocalColumn());
        self::assertSame('id', $foreign->getForeignColumn());
        self::assertSame('users', $foreign->getForeignTable());
        self::assertSame('CASCADE', $foreign->getOnDelete());
    }
}
