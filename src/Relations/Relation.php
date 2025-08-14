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
    ) {
    }

    /**
     * Execute the query and get the results.
     */
    abstract public function getResults(): mixed;

    /**
     * Set the base constraints on the relation query.
     */
    abstract protected function addConstraints(): void;
}
