<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

/**
 * @group sqlite
 */
final class QueryHelpersTest extends TestCase
{
    protected function setUp(): void
    {
        // Fake ORM con exec() y table() mínimo para pruebas
        $fakeOrm = new class() extends \VersaORM\VersaORM {
            public array $lastExecParams = [];

            public function exec(string $sql, array $bindings = [])
            {
                $this->lastExecParams = ['sql' => $sql, 'bindings' => $bindings];

                // Responder según SQL simple
                $sqlUpper = strtoupper(trim($sql));

                if (str_starts_with($sqlUpper, 'SELECT')) {
                    // Simular diferentes retornos. Si se selecciona explícitamente NAME,
                    // devolver la columna name como primer elemento para que getCell() funcione.
                    if (str_contains($sqlUpper, 'SELECT NAME')) {
                        if (str_contains($sqlUpper, 'WHERE') && str_contains($sqlUpper, '-1')) {
                            return [];
                        }
                        if (str_contains($sqlUpper, 'WHERE') || str_contains($sqlUpper, 'LIMIT 1')) {
                            return [['name' => 'one', '_table' => 'tests', 'id' => 1]];
                        }

                        return [
                            ['name' => 'one', '_table' => 'tests', 'id' => 1],
                            ['name' => 'two', '_table' => 'tests', 'id' => 2],
                        ];
                    }

                    // Por defecto, devolver filas con _table primero
                    if (str_contains($sqlUpper, 'WHERE') && str_contains($sqlUpper, '-1')) {
                        return [];
                    }
                    if (str_contains($sqlUpper, 'LIMIT 1') || str_contains($sqlUpper, 'WHERE')) {
                        return [['_table' => 'tests', 'id' => 1, 'name' => 'one']];
                    }

                    return [
                        ['_table' => 'tests', 'id' => 1, 'name' => 'one'],
                        ['_table' => 'tests', 'id' => 2, 'name' => 'two'],
                    ];
                }

                return [];
            }

            public function table(string $table, null|string $modelClass = null): QueryBuilder
            {
                // Retornar un QueryBuilder real con este ORM minimal (usaremos constructor sencillo)
                return new \VersaORM\QueryBuilder($this, $table, $modelClass);
            }

            // Sobrescribir métodos de la clase base con stubs mínimos
            public function setConfig(array $config): void
            {
            }

            public function getConfig(): array
            {
                return [];
            }

            public function metrics(): null|array
            {
                return null;
            }

            public function metricsReset(): void
            {
            }

            public function disconnect(): void
            {
            }

            public function addTypeConverter(string $name, callable $phpHandler, null|callable $dbHandler = null): void
            {
            }

            public function setTimezone(string $tz): void
            {
            }

            public function getTimezone(): string
            {
                return date_default_timezone_get();
            }

            public function logDebug(string $message, array $context = []): void
            {
            }
        };

        // Registrar fake ORM global para VersaModel
        VersaModel::setORM($fakeOrm);
    }

    public function test_getAll_returns_rows_and_applies_casting_if_present(): void
    {
        $rows = VersaModel::getAll('SELECT * FROM tests');

        static::assertIsArray($rows);
        static::assertCount(2, $rows);
        static::assertSame('one', $rows[0]['name']);
    }

    public function test_getRow_returns_single_row_or_null(): void
    {
        $row = VersaModel::getRow('SELECT * FROM tests WHERE id = ?', [1]);

        static::assertIsArray($row);
        static::assertArrayHasKey('id', $row);

        $rowNull = VersaModel::getRow('SELECT * FROM tests WHERE id = -1', []);
        static::assertNull($rowNull);
    }

    public function test_getCell_returns_first_value_or_null(): void
    {
        $cell = VersaModel::getCell('SELECT name FROM tests WHERE id = ?', [1]);

        static::assertSame('one', $cell);

        $noCell = VersaModel::getCell('SELECT missing FROM tests WHERE id = -1', []);
        static::assertNull($noCell);
    }

    public function test_query_instance_and_queryTable_static(): void
    {
        $instanceModel = new class('tests', VersaModel::getGlobalORM() ?? null) extends VersaModel {};

        $qb = $instanceModel->query();
        static::assertInstanceOf(QueryBuilder::class, $qb);

        $qb2 = VersaModel::queryTable('tests');
        static::assertInstanceOf(QueryBuilder::class, $qb2);
    }
}
