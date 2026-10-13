<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;

class HasMany extends HasOne // Extends HasOne because the constraint logic is identical
{
    /**
     * Redirigir llamadas al QueryBuilder interno.
     *
     * @param string $method
     * @param array<mixed> $arguments
     *
     * @return mixed
     *
     * @phpstan-ignore-next-line
     */
    public function __call($method, $arguments)
    {
        $this->applyConstraintsOnce();

        /** @phpstan-ignore-next-line */
        return $this->query->$method(...$arguments);
    }

    /**
     * Exponer el QueryBuilder interno para manipulación directa.
     */
    public function query(): QueryBuilder
    {
        $this->applyConstraintsOnce();

        return $this->query;
    }

    public function getResults(): mixed
    {
        $this->applyConstraintsOnce();

        return $this->query->findAll();
    }
}
