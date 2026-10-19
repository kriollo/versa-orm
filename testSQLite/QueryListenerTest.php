<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use Throwable;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
class QueryListenerTest extends TestCase
{
    protected function tearDown(): void
    {
        VersaORM::onQuery(null);
        parent::tearDown();
    }

    public function testRecibeElSqlLosParametrosYLaDuracionDeCadaConsulta(): void
    {
        $vistas = [];
        VersaORM::onQuery(static function (string $sql, array $bindings, float $ms, ?Throwable $error) use (
            &$vistas,
        ): void {
            $vistas[] = compact('sql', 'bindings', 'ms', 'error');
        });

        self::$orm->table('users')->where('email', '=', 'nadie@ejemplo.cl')->get();

        self::assertCount(1, $vistas);
        self::assertStringContainsString('users', $vistas[0]['sql']);
        self::assertSame(['nadie@ejemplo.cl'], array_values($vistas[0]['bindings']));
        self::assertGreaterThanOrEqual(0.0, $vistas[0]['ms']);
        self::assertNull($vistas[0]['error']);
    }

    public function testUnaConsultaQueFallaLlegaConSuErrorYElErrorSigueSubiendo(): void
    {
        $errores = [];
        VersaORM::onQuery(static function (string $sql, array $bindings, float $ms, ?Throwable $error) use (
            &$errores,
        ): void {
            $errores[] = $error;
        });

        try {
            self::$orm->table('tabla_que_no_existe')->get();
            self::fail('La consulta debía fallar');
        } catch (Throwable) {
            // esperado
        }

        self::assertCount(1, $errores);
        self::assertInstanceOf(Throwable::class, $errores[0]);
    }

    public function testUnEscuchadorQueFallaNoRompeLaConsulta(): void
    {
        VersaORM::onQuery(static function (): void {
            throw new \RuntimeException('el profiler falló');
        });

        self::assertIsArray(self::$orm->table('users')->get());
    }

    public function testSinEscuchadorNoSeLlamaANadie(): void
    {
        $llamadas = 0;
        VersaORM::onQuery(static function () use (&$llamadas): void {
            $llamadas++;
        });
        VersaORM::onQuery(null);

        self::$orm->table('users')->get();

        self::assertSame(0, $llamadas);
    }
}
