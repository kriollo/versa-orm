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

        static::assertSame(1, $result);
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
        static::assertNotEmpty($results);

        // Verificar que cada resultado tiene el campo 'asociado' como booleano
        foreach ($results as $result) {
            static::assertArrayHasKey('asociado', $result);
            static::assertIsBool($result['asociado']);

            // El primer módulo (id=1) debería estar asociado (true)
            if ($result['id'] === 1) {
                static::assertTrue($result['asociado'], 'El módulo Dashboard debería estar asociado');
            } else {
                // Los otros módulos deberían no estar asociados (false)
                static::assertFalse($result['asociado'], 'Los módulos no asociados deberían devolver false');
            }
        }
    }

    public function test_insertManyBooleanType(): void
    {
        $channels = [
            [
                'codigo_interno' => 'whatsapp',
                'nombre' => 'WhatsApp',
                'imagen' => '/public/dashboard/img/social/whatsapp.svg',
                'required_register' => false,
            ],
            [
                'codigo_interno' => 'telegram',
                'nombre' => 'Telegram',
                'imagen' => '/public/dashboard/img/social/telegram.svg',
                'required_register' => true,
            ],
            [
                'codigo_interno' => 'facebook_messenger',
                'nombre' => 'Facebook Messenger',
                'imagen' => '/public/dashboard/img/social/messengerf.svg',
                'required_register' => false,
            ],
            [
                'codigo_interno' => 'instagram',
                'nombre' => 'Instagram',
                'imagen' => '/public/dashboard/img/social/instagram.svg',
                'required_register' => false,
            ],
        ];
        $result = self::$orm->table('chatbot_channels')->insertMany($channels);

        static::assertSame(
            [
                'status' => 'success',
                'total_inserted' => 4,
                'batches_processed' => 1,
                'batch_size' => 1000,
                'inserted_ids' => [1, 2, 3, 4], // Si la tabla tiene autoincrement
            ],
            $result,
        );
    }
}
