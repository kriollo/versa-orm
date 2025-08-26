<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * @group sqlite
 */
final class RelationsBelongsToManyTest extends TestCase
{
    public function test_belongstomany_class_exists_and_methods(): void
    {
        $this->assertTrue(class_exists('\VersaORM\Relations\BelongsToMany'));

        $r = new ReflectionClass('\VersaORM\Relations\BelongsToMany');

        $this->assertTrue($r->hasMethod('__call'));
        $this->assertTrue($r->hasMethod('query'));
        $this->assertTrue($r->hasMethod('getResults'));
        $this->assertTrue($r->hasMethod('attach'));
        $this->assertTrue($r->hasMethod('sync'));
        $this->assertTrue($r->hasMethod('detach'));
        $this->assertTrue($r->hasMethod('addConstraints'));
    }
}
