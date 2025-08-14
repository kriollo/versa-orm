<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

class BelongsToMany extends Relation
{
    public function __construct(
        QueryBuilder $query,
        VersaModel $parent,
        public string $pivotTable,
        public string $foreignPivotKey,
        public string $relatedPivotKey,
        public string $parentKey,
        public string $relatedKey,
    ) {
        parent::__construct($query, $parent);
    }

    /**
     * @return array<int, VersaModel>
     */
    public function getResults(): array
    {
        $this->addConstraints();

        return $this->query->findAll();
    }

    protected function addConstraints(): void
    {
        $this->query->join($this->pivotTable, $this->query->getTable() . '.' . $this->relatedKey, '=', $this->pivotTable . '.' . $this->relatedPivotKey);
        $this->query->where($this->pivotTable . '.' . $this->foreignPivotKey, '=', $this->parent->getAttribute($this->parentKey));
    }
}
