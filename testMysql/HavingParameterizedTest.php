<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

/**
 * @group mysql
 */
final class HavingParameterizedTest extends TestCase
{
    public function testHavingCountParametrized(): void
    {
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as cnt'])
            ->groupBy('status')
            ->having('COUNT(*)', '>', 1)
            ->get()
        ;

        self::assertCount(1, $results);
        self::assertSame('active', $results[0]['status']);
        self::assertSame(2, $results[0]['cnt']);
    }

    public function testHavingCountBetweenParametrized(): void
    {
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as cnt'])
            ->groupBy('status')
            ->having('COUNT(*)', '>=', 1)
            ->having('COUNT(*)', '<=', 2)
            ->orderBy('status', 'asc')
            ->get()
        ;

        self::assertCount(2, $results);
        self::assertSame('active', $results[0]['status']);
        self::assertSame('inactive', $results[1]['status']);
    }
}
