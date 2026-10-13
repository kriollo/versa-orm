<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

abstract class Relation
{
    public function __construct(
        /**
         * The query builder instance for the related model.
         */
        public QueryBuilder $query,
        /**
         * The parent model instance.
         */
        protected VersaModel $parent,
    ) {}

    /** Centinela para no aplicar las restricciones más de una vez. */
    protected bool $constraintsApplied = false;

    /**
     * Execute the query and get the results.
     */
    abstract public function getResults(): mixed;

    /**
     * Set the base constraints on the relation query.
     */
    abstract protected function addConstraints(): void;

    /**
     * Aplica las restricciones de la relación una sola vez.
     *
     * __call(), query() y getResults() llaman a addConstraints() cada uno, así que
     * `$rel->query()->get()` acumulaba la misma cláusula WHERE dos veces.
     */
    protected function applyConstraintsOnce(): void
    {
        if ($this->constraintsApplied) {
            return;
        }
        $this->constraintsApplied = true;
        $this->addConstraints();
    }
}
