<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

class BelongsTo extends Relation
{
    protected string $foreignKey;
    protected string $ownerKey;
    protected string $relationName;

    public function __construct(QueryBuilder $query, VersaModel $parent, string $foreignKey, string $ownerKey, string $relationName)
    {
        $this->foreignKey = $foreignKey;
        $this->ownerKey = $ownerKey;
        $this->relationName = $relationName;
        parent::__construct($query, $parent);
    }

    protected function addConstraints(): void
    {
        $this->query->where($this->ownerKey, '=', $this->parent->getAttribute($this->foreignKey));
    }

    public function getResults()
    {
        $this->addConstraints();
        return $this->query->findOne();
    }
}
