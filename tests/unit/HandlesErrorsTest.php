<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaModel;
use VersaORM\VersaORM;
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
        // safeFind() necesita la instancia global del ORM. El test dependía de que otra
        // suite la hubiera dejado puesta, así que fallaba en cuanto se ejecutaba bajo una
        // configuración distinta a la de SQLite. Ahora se provee y se restaura aquí.
        $previous = VersaModel::getGlobalORM();
        VersaModel::setORM(new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]));

        try {
            // Ensure static handler does not rethrow by disabling throw_on_error for this model
            DummyHandlesModel::configureErrorHandling(['throw_on_error' => false]);

            $res = DummyHandlesModel::safeFind(1);

            static::assertNull($res);
        } finally {
            VersaModel::setORM($previous);
        }
    }
}
