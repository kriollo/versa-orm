<?php

declare(strict_types=1);

namespace VersaORM\SQL\Dialects;

use VersaORM\SQL\SqlDialectInterface;

use function sprintf;

class PostgreSQLDialect implements SqlDialectInterface
{
    public function quoteIdentifier(string $name): string
    {
        if (str_contains($name, '.')) {
            [$t, $c] = explode('.', $name, 2);

            if ($c === '*') {
                return sprintf('"%s".*', $t);
            }
        }

        if ($name === '*') {
            return '*';
        }

        return '"' . str_replace('"', '""', $name) . '"';
    }

    public function placeholder(int $index): string
    {
        // PDO para pgsql acepta '?', pero también soporta $1, $2...
        // Usaremos '?' para simplificar binding vía PDO.
        return '?';
    }

    public function compileLimitOffset(?int $limit, ?int $offset): string
    {
        $sql = '';

        if ($limit !== null) {
            $sql .= ' LIMIT ' . (int) $limit;
        }

        if ($offset !== null) {
            $sql .= ' OFFSET ' . (int) $offset;
        }

        return $sql;
    }

    public function getName(): string
    {
        return 'postgres';
    }
}
