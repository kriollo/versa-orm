<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

class HasOne extends Relation
{
    protected string $foreignKey;
    protected string $localKey;

    public function __construct(QueryBuilder $query, VersaModel $parent, string $foreignKey, string $localKey)
    {
        $this->foreignKey = $foreignKey;
        $this->localKey = $localKey;
        parent::__construct($query, $parent);
    }

    protected function addConstraints(): void
    {
        $this->query->where($this->foreignKey, '=', $this->parent->getAttribute($this->localKey));
    }

    public function getResults()
    {
        $this->addConstraints();
        return $this->query->findOne();
    }
}
