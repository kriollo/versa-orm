<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

final class QAHardeningStrongTest extends TestCase
{
    public function testDangerousIdentifiersAreRejected(): void
    {
        $orm = self::$orm;
        $this->expectException(\Throwable::class);
        // Nombres con backticks y comentarios
        $orm->table('users` -- ')->get();
    }

    public function testRawExpressionGuardrails(): void
    {
        $orm = self::$orm;
        // whereRaw seguro: con bindings
        $res = $orm->table('users')->whereRaw('name = ?', ['Alice'])->get();
        $this->assertIsArray($res);
        // whereRaw inseguro: sin placeholders y con ; DROP
        $this->expectException(\Throwable::class);
        $orm->table('users')->whereRaw("name = 'x'; DROP TABLE users;", [])->get();
    }

    public function testIndexCreationWithMaliciousNameFails(): void
    {
        $orm = self::$orm;
        // Asegurar estado limpio antes de crear
        try {
            $orm->schemaDrop('secure_t');
        } catch (\Throwable $e) {
            // Ignorar si no existe
        }

        $orm->schemaCreate('secure_t', [['name' => 'id', 'type' => 'INT']], ['engine' => 'InnoDB']);
        try {
            $this->expectException(\Throwable::class);
            $orm->schemaAlter('secure_t', ['addIndex' => [['name' => 'idx_bad`--', 'columns' => ['id']]]]);
        } finally {
            // Siempre limpiar al final
            try {
                $orm->schemaDrop('secure_t');
            } catch (\Throwable $e) {
                // Ignorar errores de limpieza
            }
        }
    }
}
