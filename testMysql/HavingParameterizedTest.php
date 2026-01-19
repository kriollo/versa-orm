<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

/**
 * @group mysql
 */
final class HavingParameterizedTest extends TestCase
{
    public function test_having_count_parametrized(): void
    {
        $results = self::$orm
            ->table('users')
            ->select(['status', 'COUNT(*) as cnt'])
            ->groupBy('status')
            ->having('COUNT(*)', '>', 1)
            ->get();

        static::assertCount(1, $results);
        static::assertSame('active', $results[0]['status']);
        static::assertSame(2, $results[0]['cnt']);
    }

    public function test_having_count_between_parametrized(): void
    {
        $results = self::$orm
            ->table('users')
            ->select(['status', 'COUNT(*) as cnt'])
            ->groupBy('status')
            ->having('COUNT(*)', '>=', 1)
            ->having('COUNT(*)', '<=', 2)
            ->orderBy('status', 'asc')
            ->get();

        static::assertCount(2, $results);
        static::assertSame('active', $results[0]['status']);
        static::assertSame('inactive', $results[1]['status']);
    }
}
