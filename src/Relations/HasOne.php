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

        return $this->query->findOne();
    }

    protected function addConstraints(): void
    {
        $this->query->where($this->foreignKey, '=', $this->parent->getAttribute($this->localKey));
    }
}
