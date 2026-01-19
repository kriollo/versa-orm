<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql\Schema;

use PHPUnit\Framework\TestCase;
use VersaORM\Schema\SchemaBuilder;
use VersaORM\Schema\VersaSchema;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Test básico para el nuevo SchemaBuilder.
 *
 * @group mysql
 */
class BasicSchemaBuilderTest extends TestCase
{
    private SchemaBuilder $schema;

    private VersaORM $orm;

    protected function setUp(): void
    {
        parent::setUp();

        // Crear una instancia ORM para las pruebas
        $this->orm = new VersaORM([
            'driver' => 'mysql',
            'host' => $_ENV['DB_HOST'] ?? 'localhost',
            'database' => $_ENV['DB_NAME'] ?? 'versaorm_test',
            'username' => $_ENV['DB_USER'] ?? 'root',
            'password' => $_ENV['DB_PASS'] ?? '',
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'debug' => true,
            'freeze' => false,
        ]);

        $this->schema = $this->orm->schemaBuilder();
        VersaModel::setORM($this->orm);
        VersaSchema::setORM($this->orm);
    }

    protected function tearDown(): void
    {
        try {
            $this->schema->dropIfExists('test_users');
            $this->schema->dropIfExists('test_posts');
        } catch (\Exception $e) {
            // Ignorar errores de limpieza
        }
        parent::tearDown();
    }

    public function testCanCreateBasicTable(): void
    {
        $this->schema->create('test_users', static function ($table) {
            $table->id();
            $table->string('name');
            $table->string('email', 100)->unique();
            $table->timestamps();
        });

        static::assertTrue(true);
    }

    public function testCanCreateTableWithDifferentTypes(): void
    {
        $this->schema->create('test_posts', static function ($table) {
            $table->id();
            $table->string('title', 200);
            $table->text('content');
            $table->integer('views')->default(0);
            $table->boolean('published')->default(false);
            $table->decimal('price', 8, 2)->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('published_at')->nullable();
            $table->timestamps();
        });

        static::assertTrue(true);
    }
}
