<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

class VersaORMStub4 extends VersaORM
{
    public function __construct() {}

    public function executeQuery(string $action, array $params = [])
    {
        return [];
    }
}

/**
 * @group sqlite
 */
final class QueryBuilderWheresConversionTest extends TestCase
{
    public function testProcessWheresAndConvertWheresToConditionsMapConnector(): void
    {
        $orm = new VersaORMStub4();
        $qb = new QueryBuilder($orm, 'posts');

        $ref = new \ReflectionClass($qb);

        $wheresProp = $ref->getProperty('wheres');
        $wheresProp->setAccessible(true);
        $wheresProp->setValue($qb, [
            ['column' => 'id', 'operator' => '=', 'value' => 5, 'type' => 'and'],
            ['column' => 'title', 'operator' => 'LIKE', 'value' => '%php%', 'type' => 'or'],
        ]);

        $processMethod = $ref->getMethod('processWheres');
        $processMethod->setAccessible(true);
        $processed = $processMethod->invoke($qb);

        self::assertCount(2, $processed);
        self::assertSame('id', $processed[0]['column']);

        $convertMethod = $ref->getMethod('convertWheresToConditions');
        $convertMethod->setAccessible(true);
        $conds = $convertMethod->invoke($qb);

        self::assertCount(2, $conds);
        self::assertSame('AND', $conds[0]['connector']);
        self::assertSame('OR', $conds[1]['connector']);
        self::assertSame('%php%', $conds[1]['value']);
    }
}
