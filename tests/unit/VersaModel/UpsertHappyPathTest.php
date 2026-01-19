<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
final class UpsertHappyPathTest extends TestCase
{
    public function testUpsertInsertsWhenNoExistingRecord(): void
    {
        // (No instanciamos la clase anónima aquí; la crearemos dentro de fakeOrm->table())

        $fakeOrm = new class() extends VersaORM {
            public function __construct()
            {
                parent::__construct([]);
                $this->setConfig(['driver' => 'sqlite', 'engine' => 'pdo']);
            }

            public function isFrozen(): bool
            {
                return true; // evitar ensureColumnsExist
            }

            public function isModelFrozen(string $modelClass): bool
            {
                return true;
            }

            public function table(string $table, ?string $modelClass = null): \VersaORM\QueryBuilder
            {
                return new class($this, $table, $modelClass) extends \VersaORM\QueryBuilder {
                    public function upsert(array $attributes, array $uniqueKeys, array $updateColumns = []): array
                    {
                        return ['operation' => 'inserted_or_updated'];
                    }

                    public function firstArray(): ?array
                    {
                        return ['id' => 555];
                    }
                };
            }

            public function exec(string $sql, array $params = [])
            {
                return [];
            }
        };

        $m = new class('users', $fakeOrm) extends VersaModel {
            protected array $fillable = ['email'];

            public function validate(): array
            {
                return [];
            }

            public function getData(): array
            {
                return ['email' => 'x@example.test'];
            }
        };

        // Clear listeners
        VersaModel::clearEventListeners();

        $m->fill(['email' => 'x@example.test']);
        $res = $m->upsert(['email']);

        static::assertIsArray($res);
        static::assertArrayHasKey('operation', $res);
        static::assertSame('inserted_or_updated', $res['operation']);
        static::assertSame(555, $m->getAttribute('id'));
    }
}
