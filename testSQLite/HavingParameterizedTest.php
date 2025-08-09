<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

final class HavingParameterizedTest extends TestCase
{
    public function testHavingCountParametrized(): void
    {
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as cnt'])
            ->groupBy('status')
            ->having('COUNT(*)', '>', 1)
            ->get();

        $this->assertCount(1, $results);
        $this->assertEquals('active', $results[0]['status']);
        $this->assertEquals(2, $results[0]['cnt']);
    }

    public function testHavingCountBetweenParametrized(): void
    {
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as cnt'])
            ->groupBy('status')
            ->having('COUNT(*)', '>=', 1)
            ->having('COUNT(*)', '<=', 2)
            ->orderBy('status', 'asc')
            ->get();

        $this->assertCount(2, $results);
        $this->assertEquals('active', $results[0]['status']);
        $this->assertEquals('inactive', $results[1]['status']);
    }
}
