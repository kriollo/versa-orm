<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
final class StoreHappyPathTest extends TestCase
{
    public function testStoreReturnsInsertedIdAndSetsAttribute(): void
    {
        // Crear un QueryBuilder falso que devuelva 123 como insertGetId
        $fakeQb = new class(null, 'users', null) extends \VersaORM\QueryBuilder {
            public static bool $called = false;

            public function __construct($orm, string $table, ?string $modelClass = null)
            {
                // llamar al padre con valores mínimos
                parent::__construct($orm, $table, $modelClass);
            }

            public function insertGetId(array $data): ?int
            {
                self::$called = true;
                file_put_contents(sys_get_temp_dir() . '/versa_store_spy.txt', "called\n", FILE_APPEND);

                return 123;
            }

            public function getModelInstance(): \VersaORM\VersaModel
            {
                return new class('users', null) extends VersaModel {
                    public function getData(): array
                    {
                        return [];
                    }
                };
            }

            public function getTable(): string
            {
                return 'users';
            }
        };

        // Crear un VersaORM falso que devuelva el QueryBuilder falso (firma compatible)
        $fakeOrm = new class($fakeQb) extends VersaORM {
            private $qb;

            public function __construct($qb)
            {
                parent::__construct([]);
                $this->qb = $qb;
            }

            public function table(string $table, ?string $modelClass = null): \VersaORM\QueryBuilder
            {
                return $this->qb;
            }

            public function exec(string $sql, array $params = [])
            {
                return [];
            }
        };

        // Registrar ORM global (no necesario si lo pasamos por instancia)
        VersaModel::setORM(null);

        $m = new class('users', $fakeOrm) extends VersaModel {
            protected array $fillable = ['name'];

            public function validate(): array
            {
                return [];
            }

            public function getData(): array
            {
                return ['name' => 'bob'];
            }
        };

        $m->fill(['name' => 'bob']);

        // Asegurar que no hay listeners que cancelen la operación
        VersaModel::clearEventListeners();

        $id = $m->store();

        // Asegurarse de que insertGetId fue invocado
        static::assertTrue($fakeQb::${'called'});
        static::assertSame(123, $id);
        static::assertSame(123, $m->getAttribute('id'));
    }
}
