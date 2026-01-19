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

        $this->assertSame($data, $constraints->data);
        $this->assertEquals('id', $constraints->primary_key);
        $this->assertEquals(['age > 18'], $constraints->checks);
        $this->assertNull($constraints->non_existent);
    }

    public function testSet(): void
    {
        $constraints = new TableConstraintsDef();
        $constraints->unique = ['email'];

        $this->assertEquals(['email'], $constraints->unique);
        $this->assertEquals(['email'], $constraints->data['unique']);
    }

    public function testIsset(): void
    {
        $constraints = new TableConstraintsDef(['primary_key' => 'id']);

        $this->assertTrue(isset($constraints->primary_key));
        $this->assertFalse(isset($constraints->unique));
    }
}
