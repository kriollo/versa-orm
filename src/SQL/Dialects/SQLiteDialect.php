<?php

declare(strict_types=1);

namespace VersaORM\SQL\Dialects;

use VersaORM\SQL\SqlDialectInterface;

class SQLiteDialect implements SqlDialectInterface
{
    public function quoteIdentifier(string $name): string
    {
        if ($name === '*') {
            return '*';
        }
        if (str_contains($name, '.')) {
            [$t, $c] = explode('.', $name, 2);
            if ($c === '*') {
                return sprintf('"%s".*', $t);
            }
        }
        return '"' . str_replace('"', '""', $name) . '"';
    }

    public function placeholder(int $index): string
    {
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
        return 'sqlite';
    }
}
