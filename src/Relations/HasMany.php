<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;

class HasMany extends HasOne // Extends HasOne because the constraint logic is identical
{
    /**
     * Redirigir llamadas al QueryBuilder interno.
     */
    public function __call($method, $arguments)
    {
        $this->addConstraints();

        return $this->query->$method(...$arguments);
    }

    /**
     * Exponer el QueryBuilder interno para manipulación directa.
     */
    public function query(): QueryBuilder
    {
        $this->addConstraints();

        return $this->query;
    }

    public function getResults(): mixed
    {
        $this->addConstraints();

        return $this->query->findAll();
    }
}
