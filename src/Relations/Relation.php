<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

abstract class Relation
{
    /**
     * The query builder instance for the related model.
     */
    public QueryBuilder $query;

    /**
     * The parent model instance.
     */
    protected VersaModel $parent;

    public function __construct(QueryBuilder $query, VersaModel $parent)
    {
        $this->query  = $query;
        $this->parent = $parent;
    }

    /**
     * Set the base constraints on the relation query.
     */
    abstract protected function addConstraints(): void;

    /**
     * Execute the query and get the results.
     *
     * @return mixed
     */
    abstract public function getResults();
}
