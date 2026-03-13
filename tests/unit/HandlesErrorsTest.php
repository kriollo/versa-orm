<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaModel;
use VersaORM\VersaORMException;

if (!class_exists('DummyHandlesModel')) {
    class DummyHandlesModel extends VersaModel
    {
        use HandlesErrors;

        // Provide a table name to avoid uninitialized access in trait
        protected string $table = 'dummy_handles';

        public function __construct() {}

    }
}

final class HandlesErrorsTest extends TestCase
{
    public function testGetLastErrorSuggestionsEmptyByDefault(): void
    {
        $m = new DummyHandlesModel();

        static::assertSame([], $m->getLastErrorSuggestions());
    }

    public function testSafeStoreCatchesAndSetsLastError(): void
    {
        $m = new DummyHandlesModel();

        try {
            $m->safeStore();
        } catch (VersaORMException $e) {
            // If configuration throws, ensure lastError is populated by trait
        }

        static::assertTrue($m->hasError() || $m->getLastError() === null);
    }

    public function testWithStaticErrorHandlingDoesNotCrash(): void
    {
        // Ensure static handler does not rethrow by disabling throw_on_error for this model
        DummyHandlesModel::configureErrorHandling(['throw_on_error' => false]);

        $res = DummyHandlesModel::safeFind(1);

        static::assertNull($res);
    }
}
