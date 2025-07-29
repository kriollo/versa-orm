<?php

// tests/StressTest.php

declare(strict_types=1);

namespace VersaORM\Tests;

class StressTest extends TestCase
{
    /**
     * @group stress
     */
    public function testMassiveInserts(): void
    {
        $iterations = 500;
        $startTime = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            self::$orm->table('users')->insert([
                'name' => 'User ' . $i,
                'email' => 'user' . $i . '@stresstest.com',
                'status' => 'stress_test'
            ]);
        }

        $duration = microtime(true) - $startTime;

        $count = self::$orm->table('users')->where('status', '=', 'stress_test')->count();
        $this->assertEquals($iterations, $count);

        // Asert that the operation was reasonably fast. 
        // This is not a strict benchmark, but a sanity check.
        // e.g., less than 5 seconds for 500 inserts.
        $this->assertLessThan(5, $duration, "Massive inserts took too long.");
        
        echo sprintf("\n[StressTest] Inserted %d records in %.2f seconds.", $iterations, $duration);
    }

    /**
     * @group stress
     * @depends testMassiveInserts
     */
    public function testMassiveReads(): void
    {
        // First, ensure there is data to read
        $this->testMassiveInserts();

        $iterations = 500;
        $startTime = microtime(true);

        $users = self::$orm->table('users')->where('status', '=', 'stress_test')->findAll();

        $duration = microtime(true) - $startTime;

        $this->assertCount($iterations, $users);

        $this->assertLessThan(3, $duration, "Massive reads took too long.");

        echo sprintf("\n[StressTest] Read %d records in %.2f seconds.", $iterations, $duration);
    }
}
