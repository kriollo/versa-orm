<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoConnection;

/**
 * @group sqlite
 */
final class PdoConnectionTest extends TestCase
{
    public function test_sqlite_file_pool_reuse_and_foreign_keys(): void
    {
        $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'versa_test_' . uniqid() . '.sqlite';

        $config = [
            'driver' => 'sqlite',
            'database' => $tmp,
            'options' => ['enable_foreign_keys' => true],
        ];

        $c1 = new PdoConnection($config);
        $pdo1 = $c1->getPdo();

        $c2 = new PdoConnection($config);
        $pdo2 = $c2->getPdo();

        // File-backed sqlite should reuse same PDO instance from the pool
        $this->assertSame($pdo1, $pdo2);

        // foreign_keys pragma should be enabled
        $stmt = $pdo1->query('PRAGMA foreign_keys');
        $val = $stmt !== false ? $stmt->fetchColumn() : null;
        $this->assertEquals('1', (string) $val);

        // cleanup
        $c1->close();
        $c2->close();
        if (file_exists($tmp)) {
            @unlink($tmp);
        }
    }

    public function test_sqlite_memory_does_not_reuse_pool(): void
    {
        $config = [
            'driver' => 'sqlite',
            'database' => ':memory:',
        ];

        $c1 = new PdoConnection($config);
        $pdo1 = $c1->getPdo();

        $c2 = new PdoConnection($config);
        $pdo2 = $c2->getPdo();

        // In-memory sqlite should not reuse pooled connection
        $this->assertNotSame($pdo1, $pdo2);

        $c1->close();
        $c2->close();
    }
}
