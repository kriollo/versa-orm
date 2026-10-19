<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use PDO;
use PHPUnit\Framework\TestCase as BaseTestCase;
use VersaORM\VersaORM;

/**
 * Una consulta de lectura no debe dejar su cursor abierto: la conexión quedaba en una lectura vieja
 * y, cuando otra conexión escribía, ya no podía escribir («database is locked») mientras durara el
 * proceso (un worker de cola, una suite de pruebas).
 *
 * @group sqlite
 */
class CursorLockTest extends BaseTestCase
{
    private string $file;

    protected function setUp(): void
    {
        $this->file = sys_get_temp_dir() . '/versaorm_lock_' . bin2hex(random_bytes(4)) . '.sqlite';
    }

    protected function tearDown(): void
    {
        @unlink($this->file);
    }

    /** @return array<string, array{string}> */
    public static function lecturas(): array
    {
        return ['count' => ['count'], 'exists' => ['exists'], 'first' => ['first'], 'get' => ['get']];
    }

    /** @dataProvider lecturas */
    public function testDespuesDeUnaLecturaLaConexionSigueEscribiendo(string $metodo): void
    {
        $orm = new VersaORM(['engine' => 'pdo', 'driver' => 'sqlite', 'database' => $this->file]);
        $orm->exec('CREATE TABLE items (id INTEGER PRIMARY KEY, nombre TEXT)');
        $orm->exec("INSERT INTO items (nombre) VALUES ('a'), ('b')");

        $orm->table('items')->where('id', '>', 0)->{$metodo}();

        // Otra conexión escribe (otro proceso, o la base de pruebas) y después escribe la del ORM
        $otra = new PDO('sqlite:' . $this->file, options: [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 0]);
        $otra->exec("INSERT INTO items (nombre) VALUES ('c')");
        $orm->exec("UPDATE items SET nombre = 'z' WHERE id = 1");

        self::assertSame('z', $otra->query('SELECT nombre FROM items WHERE id = 1')->fetchColumn());
    }
}
