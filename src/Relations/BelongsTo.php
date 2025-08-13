<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

class BelongsTo extends Relation
{
    public string $foreignKey;

    public string $ownerKey;

    public string $relationName;

    public function __construct(QueryBuilder $query, VersaModel $parent, string $foreignKey, string $ownerKey, string $relationName)
    {
        $this->foreignKey   = $foreignKey;
        $this->ownerKey     = $ownerKey;
        $this->relationName = $relationName;
        parent::__construct($query, $parent);
    }

    public function getResults()
    {
        $this->addConstraints();

        return $this->query->findOne();
    }

    protected function addConstraints(): void
    {
        $this->query->where($this->ownerKey, '=', $this->parent->getAttribute($this->foreignKey));
    }
}
