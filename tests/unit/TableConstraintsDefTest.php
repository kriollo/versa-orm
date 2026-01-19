<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\TableConstraintsDef;

/**
 * @group core
 */
class TableConstraintsDefTest extends TestCase
{
    public function testConstructAndGet(): void
    {
        $data = ['primary_key' => 'id', 'checks' => ['age > 18']];
        $constraints = new TableConstraintsDef($data);

        static::assertSame($data, $constraints->data);
        static::assertSame('id', $constraints->primary_key);
        static::assertEquals(['age > 18'], $constraints->checks);
        static::assertNull($constraints->non_existent);
    }

    public function testSet(): void
    {
        $constraints = new TableConstraintsDef();
        $constraints->unique = ['email'];

        static::assertEquals(['email'], $constraints->unique);
        static::assertEquals(['email'], $constraints->data['unique']);
    }

    public function testIsset(): void
    {
        $constraints = new TableConstraintsDef(['primary_key' => 'id']);

        static::assertTrue(isset($constraints->primary_key));
        static::assertFalse(isset($constraints->unique));
    }
}
