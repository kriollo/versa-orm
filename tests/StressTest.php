<?php

// tests/StressTest.php

declare(strict_types=1);

namespace VersaORM\Tests;

class StressTest extends TestCase
{
    private const ITERATIONS = 1000; // Aumentado para un test más riguroso

    protected function setUp(): void
    {
        // No llamar al parent::setUp() para evitar transacciones
        // Limpiar la tabla de usuarios antes de cada prueba de estrés
        self::$orm->exec('DELETE FROM users WHERE status LIKE \'stress_test%\'');
    }

    protected function tearDown(): void
    {
        // No llamar al parent::tearDown()
        // Limpiar después de las pruebas de estrés
        self::$orm->exec('DELETE FROM users WHERE status LIKE \'stress_test%\'');
    }


    /**
     * @group stress
     */
    public function testMassiveInserts(): void
    {
        $startTime = microtime(true);

        for ($i = 0; $i < self::ITERATIONS; $i++) {
            self::$orm->table('users')->insert([
                'name' => 'User ' . $i,
                'email' => 'user' . $i . '@stresstest.com',
                'status' => 'stress_test_insert'
            ]);
        }

        $duration = microtime(true) - $startTime;

        $count = self::$orm->table('users')->where('status', '=', 'stress_test_insert')->count();
        $this->assertEquals(self::ITERATIONS, $count);

        // Permitir más tiempo para sistemas lentos y CI
        $this->assertLessThan(120, $duration, 'Massive inserts took too long.');
        
        echo sprintf("\n[StressTest] Inserted %d records in %.4f seconds.", self::ITERATIONS, $duration);
    }

    /**
     * @group stress
     * @depends testMassiveInserts
     */
    public function testMassiveReads(): void
    {
        // Asegurar que hay datos para leer
        $this->testMassiveInserts();

        $startTime = microtime(true);

        $users = self::$orm->table('users')->where('status', '=', 'stress_test_insert')->findAll();

        $duration = microtime(true) - $startTime;

        $this->assertCount(self::ITERATIONS, $users);

        $this->assertLessThan(10, $duration, "Massive reads took too long.");

        echo sprintf("\n[StressTest] Read %d records in %.4f seconds.", self::ITERATIONS, $duration);
    }

    /**
     * @group stress
     * @depends testMassiveInserts
     */
    public function testMassiveUpdates(): void
    {
        // Asegurar que hay datos para actualizar
        $this->testMassiveInserts();

        $startTime = microtime(true);

        $updatedCount = self::$orm->table('users')
            ->where('status', '=', 'stress_test_insert')
            ->update(['status' => 'stress_test_update']);

        $duration = microtime(true) - $startTime;

        $this->assertEquals(self::ITERATIONS, $updatedCount);

        $this->assertLessThan(120, $duration, "Massive updates took too long.");

        echo sprintf("\n[StressTest] Updated %d records in %.4f seconds.", $updatedCount, $duration);
    }

    /**
     * @group stress
     * @depends testMassiveUpdates
     */
    public function testMassiveDeletes(): void
    {
        // Asegurar que hay datos para eliminar
        $this->testMassiveUpdates();

        $startTime = microtime(true);

        $deletedCount = self::$orm->table('users')
            ->where('status', '=', 'stress_test_update')
            ->delete();

        $duration = microtime(true) - $startTime;

        $this->assertEquals(self::ITERATIONS, $deletedCount);

        $this->assertLessThan(120, $duration, "Massive deletes took too long.");

        echo sprintf("\n[StressTest] Deleted %d records in %.4f seconds.", $deletedCount, $duration);
    }
}
