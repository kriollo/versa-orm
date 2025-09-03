<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;

class SaveNoDateDateTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    public function test_store_new_record(): void
    {
        $data = VersaModel::dispense('test_save');
        $data->data = 'Test data';
        $result = $data->store();

        self::assertSame(1, $result);
    }

    public function test_boolean_case_query(): void
    {
        $idEmpresa = 1;

        $sql = 'SELECT
                    m.id,
                    m.nombre,
                    CASE WHEN em.id_modulo IS NULL THEN false ELSE true END AS asociado,
                    m.icono,
                    m.fill
                FROM
                    versa_menu m
                    LEFT JOIN empresa_modulo em ON m.id = em.id_modulo
                    AND em.id_empresa = ?
                WHERE
                    m.estado = true
                ORDER BY
                    m.seccion,
                    m.posicion';

        $results = self::$orm->exec($sql, [$idEmpresa]);

        // Verificar que se obtuvieron resultados
        self::assertNotEmpty($results);

        // Verificar que cada resultado tiene el campo 'asociado' como booleano
        foreach ($results as $result) {
            self::assertArrayHasKey('asociado', $result);
            self::assertIsBool($result['asociado']);

            // El primer módulo (id=1) debería estar asociado (true)
            if ($result['id'] === 1) {
                self::assertTrue($result['asociado'], 'El módulo Dashboard debería estar asociado');
            } else {
                // Los otros módulos deberían no estar asociados (false)
                self::assertFalse($result['asociado'], 'Los módulos no asociados deberían devolver false');
            }
        }
    }
}
