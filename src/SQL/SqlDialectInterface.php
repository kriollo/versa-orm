<?php

declare(strict_types=1);

namespace VersaORM\SQL;

interface SqlDialectInterface
{
    public function quoteIdentifier(string $name): string;

    public function placeholder(int $index): string;

    public function compileLimitOffset(?int $limit, ?int $offset): string;

    /**
     * Nombre simple del dialecto/driver para decisiones condicionales.
     */
    public function getName(): string;
}
