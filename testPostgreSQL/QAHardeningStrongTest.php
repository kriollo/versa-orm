<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

final class QAHardeningStrongTest extends TestCase
{
    public function testDangerousIdentifiersAreRejected(): void
    {
        $orm = self::$orm;
        $this->expectException(\Throwable::class);
        // Nombres con comillas y comentario
        $orm->table("users\"; -- ")->get();
    }

    public function testRawExpressionGuardrails(): void
    {
        $orm = self::$orm;
        $res = $orm->table('users')->whereRaw('name = ?', ['Alice'])->get();
        $this->assertIsArray($res);
        $this->expectException(\Throwable::class);
        $orm->table('users')->whereRaw("name = 'x'; DROP TABLE users; --", [])->get();
    }

    public function testIndexCreationWithMaliciousNameFails(): void
    {
        $orm = self::$orm;
        $orm->schemaCreate('secure_t', [['name' => 'id', 'type' => 'INT']]);
        $this->expectException(\Throwable::class);
        $orm->schemaAlter('secure_t', ['addIndex' => [['name' => 'idx_bad";--', 'columns' => ['id']]]]);
        $orm->schemaDrop('secure_t');
    }
}
