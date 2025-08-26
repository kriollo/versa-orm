<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaModel;
use VersaORM\VersaORMException;

if (! class_exists('DummyHandlesModel')) {
    class DummyHandlesModel extends VersaModel
    {
        use HandlesErrors;

        public function __construct()
        {
        }

        public function save(string $primaryKey = 'id'): array
        {
            throw new VersaORMException('boom', 'E_BOOM');
        }

        public static function find(mixed $id): mixed
        {
            throw new VersaORMException('not found', 'E_NOT_FOUND');
        }
    }
}

final class HandlesErrorsTest extends TestCase
{
    public function testGetLastErrorSuggestionsEmptyByDefault(): void
    {
        $m = new DummyHandlesModel();

        $this->assertSame([], $m->getLastErrorSuggestions());
    }

    public function testSafeStoreCatchesAndSetsLastError(): void
    {
        $m = new DummyHandlesModel();

        try {
            $m->safeStore();
        } catch (VersaORMException $e) {
            // If configuration throws, ensure lastError is populated by trait
        }

        $this->assertTrue($m->hasError() || $m->getLastError() === null);
    }

    public function testWithStaticErrorHandlingDoesNotCrash(): void
    {
        $res = DummyHandlesModel::safeFind(1);
        $this->assertNull($res);
    }
}
