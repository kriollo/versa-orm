<?php

declare(strict_types=1);

namespace VersaORM\Relations;

class HasMany extends HasOne // Extends HasOne because the constraint logic is identical
{
    public function getResults()
    {
        $this->addConstraints();
        return $this->query->findAll();
    }
}
