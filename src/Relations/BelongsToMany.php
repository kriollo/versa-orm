<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

class BelongsToMany extends Relation
{
    protected string $pivotTable;
    protected string $foreignPivotKey;
    protected string $relatedPivotKey;
    protected string $parentKey;
    protected string $relatedKey;

    public function __construct(
        QueryBuilder $query,
        VersaModel $parent,
        string $pivotTable,
        string $foreignPivotKey,
        string $relatedPivotKey,
        string $parentKey,
        string $relatedKey
    ) {
        $this->pivotTable = $pivotTable;
        $this->foreignPivotKey = $foreignPivotKey;
        $this->relatedPivotKey = $relatedPivotKey;
        $this->parentKey = $parentKey;
        $this->relatedKey = $relatedKey;

        parent::__construct($query, $parent);
    }

    protected function addConstraints(): void
    {
        $this->query->join($this->pivotTable, $this->query->getTable() . '.' . $this->relatedKey, '=', $this->pivotTable . '.' . $this->relatedPivotKey);
        $this->query->where($this->pivotTable . '.' . $this->foreignPivotKey, '=', $this->parent->getAttribute($this->parentKey));
    }

    public function getResults()
    {
        $this->addConstraints();
        return $this->query->findAll();
    }
}
