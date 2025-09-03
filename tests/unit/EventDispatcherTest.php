<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\EventDispatcher;
use VersaORM\ModelEvent;

final class EventDispatcherTest extends TestCase
{
    public function testListenAndDispatch(): void
    {
        $called = [];

        // Stub implementation in-place
        $dispatcher = new class($called) implements EventDispatcher {
            private $listeners = [];

            private $calledRef;

            public function __construct(&$calledRef)
            {
                $this->calledRef = &$calledRef;
            }

            public function listen(string $event, callable $listener): void
            {
                $this->listeners[$event][] = $listener;
            }

            public function dispatch(string $event, ModelEvent $context): bool
            {
                foreach ($this->listeners[$event] ?? [] as $l) {
                    $res = $l($context);
                    $this->calledRef[] = $res;
                    if ($res === false) {
                        return false;
                    }
                }

                return true;
            }
        };

        $dispatcher->listen('creating', function (ModelEvent $e) {
            return true;
        });
        $dispatcher->listen('creating', function (ModelEvent $e) {
            return false;
        });

        $result = $dispatcher->dispatch('creating', new ModelEvent((object) [], []));

        static::assertFalse($result);
        static::assertNotEmpty($called);
    }
}
