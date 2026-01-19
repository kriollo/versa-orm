<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\Blueprint;
use VersaORM\Schema\SchemaBuilder;
use VersaORM\VersaORM;

/**
 * @group core
 */
class SchemaBuilderTest extends TestCase
{
    private $orm;

    protected function setUp(): void
    {
        // Mock VersaORM to avoid actual DB connection
        $this->orm = $this->createMock(VersaORM::class);
        $this->orm->method('getConfig')->willReturn(['driver' => 'sqlite']);
        $this->orm->method('exec')->willReturn(0);
    }

    public function test_create_table_executes_sql(): void
    {
        $schema = new SchemaBuilder($this->orm);

        // Match the exact SQL generated for SQLite
        $this->orm
            ->expects(self::once())
            ->method('exec')
            ->with(self::stringContains(
                'CREATE TABLE "users" ("id" INTEGER, "name" TEXT NOT NULL, PRIMARY KEY ("id"))',
            ));

        $schema->create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
        });
    }

    public function test_drop_table(): void
    {
        $schema = new SchemaBuilder($this->orm);

        $this->orm
            ->expects(self::once())
            ->method('schemaDrop')
            ->with('users', false);

        $schema->drop('users');
    }

    public function test_drop_if_exists(): void
    {
        $schema = new SchemaBuilder($this->orm);

        $this->orm
            ->expects(self::once())
            ->method('schemaDrop')
            ->with('users', true);

        $schema->dropIfExists('users');
    }

    public function test_rename_table(): void
    {
        $schema = new SchemaBuilder($this->orm);

        $this->orm
            ->expects(self::once())
            ->method('schemaRename')
            ->with('old', 'new');

        $schema->rename('old', 'new');
    }

    public function test_has_table(): void
    {
        $schema = new SchemaBuilder($this->orm);

        $this->orm
            ->method('schema')
            ->with('tables')
            ->willReturn([
                ['name' => 'users'],
                ['name' => 'posts'],
            ]);

        self::assertTrue($schema->hasTable('users'));
        self::assertFalse($schema->hasTable('missing'));
    }

    public function test_has_column(): void
    {
        $schema = new SchemaBuilder($this->orm);

        $this->orm
            ->method('schema')
            ->with('columns', 'users')
            ->willReturn([
                ['name' => 'id'],
                ['name' => 'name'],
            ]);

        self::assertTrue($schema->hasColumn('users', 'name'));
        self::assertFalse($schema->hasColumn('users', 'email'));
    }

    public function test_foreign_key_constraints_sqlite(): void
    {
        $schema = new SchemaBuilder($this->orm);

        $this->orm
            ->expects($this->exactly(2))
            ->method('exec')
            ->willReturnCallback(function ($sql) {
                static $count = 0;
                if ($count === 0) {
                    $this->assertEquals('PRAGMA foreign_keys = OFF', $sql);
                } else {
                    $this->assertEquals('PRAGMA foreign_keys = ON', $sql);
                }
                $count++;

                return 0;
            });

        $schema->disableForeignKeyConstraints();
        $schema->enableForeignKeyConstraints();
    }
}
