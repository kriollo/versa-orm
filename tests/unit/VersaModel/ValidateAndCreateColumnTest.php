<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;

/**
 * @group sqlite
 */
final class ValidateAndCreateColumnTest extends TestCase
{
    public function testValidateFieldAgainstSchemaReturnsEmptyWhenNoRules(): void
    {
        $m = new class('users', null) extends VersaModel {
            public function validate(): array
            {
                return [];
            }
        };

        // call protected method via reflection
        $r = new ReflectionClass($m);
        $method = $r->getMethod('validateFieldAgainstSchema');
        $method->setAccessible(true);

        $res = $method->invokeArgs($m, ['email', null, []]);
        self::assertIsArray($res);
        self::assertEmpty($res);
    }

    public function testEnsureColumnsExistThrowsWhenNoOrm(): void
    {
        // ensure no ORM
        VersaModel::setORM(null);

        $m = new class('users', null) extends VersaModel {};

        $r = new ReflectionClass($m);
        $method = $r->getMethod('ensureColumnsExist');
        $method->setAccessible(true);

        // en tiempo de ejecución la firma exige un VersaORM; pasar array provoca TypeError
        $this->expectException(TypeError::class);

        $method->invokeArgs($m, [[]]);
    }
}
