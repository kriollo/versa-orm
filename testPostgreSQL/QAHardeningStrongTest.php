<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use Throwable;

final class QAHardeningStrongTest extends TestCase
{
    public function test_dangerous_identifiers_are_rejected(): void
    {
        $orm = self::$orm;
        $this->expectException(Throwable::class);
        // Nombres con comillas y comentario
        $orm->table('users"; -- ')->get();
    }

    public function test_raw_expression_guardrails(): void
    {
        $orm = self::$orm;
        $res = $orm->table('users')->whereRaw('name = ?', ['Alice'])->get();
        static::assertIsArray($res);
        $this->expectException(Throwable::class);
        $orm->table('users')->whereRaw("name = 'x'; DROP TABLE users; --", [])->get();
    }

    public function test_index_creation_with_malicious_name_fails(): void
    {
        $orm = self::$orm;

        // Asegurar estado limpio
        try {
            $orm->schemaDrop('secure_t');
        } catch (Throwable $e) {
            // ignorar si no existe
        }

        $orm->schemaCreate('secure_t', [['name' => 'id', 'type' => 'INT']]);

        try {
            $this->expectException(Throwable::class);
            $orm->schemaAlter('secure_t', ['addIndex' => [['name' => 'idx_bad";--', 'columns' => ['id']]]]);
        } finally {
            // Siempre limpiar
            try {
                $orm->schemaDrop('secure_t');
            } catch (Throwable $e) {
                // ignorar
            }
        }
    }
}
