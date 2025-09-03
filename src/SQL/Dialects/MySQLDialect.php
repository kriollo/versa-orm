<?php

declare(strict_types=1);

namespace VersaORM\SQL\Dialects;

use VersaORM\SQL\SqlDialectInterface;

use function sprintf;

class MySQLDialect implements SqlDialectInterface
{
    public function quoteIdentifier(string $name): string
    {
        // Permitir alias "table.*"
        if (str_contains($name, '.')) {
            [$t, $c] = explode('.', $name, 2);

            if ($c === '*') {
                return sprintf('`%s`.*', $t);
            }
        }

        if ($name === '*') {
            return '*';
        }

        return '`' . str_replace('`', '``', $name) . '`';
    }

    public function placeholder(int $index): string
    {
        return '?';
    }

    public function compileLimitOffset(null|int $limit, null|int $offset): string
    {
        $sql = '';

        if ($limit !== null) {
            $sql .= ' LIMIT ' . $limit;
        }

        if ($offset !== null) {
            $sql .= ' OFFSET ' . $offset;
        }

        return $sql;
    }

    public function getName(): string
    {
        return 'mysql';
    }
}
