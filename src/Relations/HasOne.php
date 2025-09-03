<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

class HasOne extends Relation
{
    public function __construct(
        QueryBuilder $query,
        VersaModel $parent,
        public string $foreignKey,
        public string $localKey,
    ) {
        parent::__construct($query, $parent);
    }

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

        return $this->query->findOne();
    }

    protected function addConstraints(): void
    {
        $this->query->where($this->foreignKey, '=', $this->parent->getAttribute($this->localKey));
    }
}
