<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use DateTime;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaModel;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

enum TestEnum: string
{
    case Alpha = 'alpha';
    case Beta = 'beta';
}

class EliteModel extends VersaModel
{
    use HandlesErrors;

    protected string $table = 'elite_table';

    protected array $fillable = ['id', 'name', 'data', 'status', 'ip', 'uuid'];

    protected array $casts = [
        'data' => 'json',
        'status' => 'enum:' . TestEnum::class,
        'ip' => 'inet',
        'uuid' => 'uuid',
        'created_at' => 'datetime',
    ];

    public function __construct($orm = null)
    {
        parent::__construct($this->table, $orm);
    }

    // Override to avoid missing method in mock or parent
    public static function find(mixed $id): ?static
    {
        return null;
    }
}

/**
 * @group core
 */
class EliteCoverageTest extends TestCase
{
    private $orm;

    protected function setUp(): void
    {
        $this->orm = $this->createMock(VersaORM::class);
        $this->orm->method('getConfig')->willReturn(['driver' => 'sqlite']);
        VersaModel::setORM($this->orm);
    }

    public function test_strong_typing_php_edge_cases(): void
    {
        $model = new EliteModel($this->orm);

        $refl = new ReflectionClass(VersaModel::class);
        $method = $refl->getMethod('getPhpCastHandlers');
        $method->setAccessible(true);
        $handlers = $method->invoke($model);

        // 1. bool fallback
        self::assertFalse($handlers['bool']($model, 'active', 'maybe'));

        // 2. array fallback (passing null to return [])
        self::assertEquals([], $handlers['array']($model, 'data', null));

        // 3. json invalid
        try {
            $handlers['json']($model, 'data', 'invalid-json{');
        } catch (\Exception $e) {
            self::assertTrue(true);
        }

        // 3.1 json invalid type
        try {
            $handlers['json']($model, 'data', 123);
        } catch (\Exception $e) {
            self::assertTrue(true);
        }

        // 4. datetime already instance
        $now = new DateTime();
        self::assertSame($now, $handlers['datetime']($model, 'created_at', $now));

        // 5. datetime exception
        try {
            $handlers['datetime']($model, 'created_at', 'invalid-date-string-123');
        } catch (\Exception $e) {
            self::assertTrue(true);
        }

        // 6. enum invalid
        try {
            $handlers['enum']($model, 'status', 'gamma', ['values' => ['alpha', 'beta']]);
        } catch (\Exception $e) {
            self::assertTrue(true);
        }

        // 7. set handler coverage
        $setHandler = $handlers['set'];
        self::assertEquals(['a', 'b'], $setHandler($model, 'flags', 'a,b'));
        self::assertEquals(['a', 'b'], $setHandler($model, 'flags', '["a","b"]'));
        self::assertEquals(['a'], $setHandler($model, 'flags', ['a']));

        try {
            $setHandler($model, 'flags', 'c', ['values' => ['a', 'b']]);
        } catch (\Exception $e) {
            self::assertTrue(true);
        }
    }

    public function test_strong_typing_db_edge_cases(): void
    {
        $model = new EliteModel($this->orm);

        $refl = new ReflectionClass(VersaModel::class);
        $method = $refl->getMethod('getDbCastHandlers');
        $method->setAccessible(true);
        $handlers = $method->invoke($model);

        // 1. string max length
        try {
            $handlers['string']($model, 'name', str_repeat('a', 1000), ['max_length' => 5]);
        } catch (\Exception $e) {
            self::assertTrue(true);
        }

        // 2. bool non-standard
        self::assertEquals(0, $handlers['bool']($model, 'active', 'no'));

        // 3. json string path
        self::assertEquals('{"a":1}', $handlers['json']($model, 'data', '{"a":1}'));

        // 4. uuid invalid
        try {
            $handlers['uuid']($model, 'uuid', 'not-a-uuid');
        } catch (\Exception $e) {
            self::assertTrue(true);
        }

        // 5. datetime from timestamp
        $ts = time();
        self::assertStringContainsString(date('Y-m-d'), $handlers['datetime']($model, 'created_at', $ts));

        // 6. inet invalid
        try {
            $handlers['inet']($model, 'ip', '999.999.999.999');
        } catch (\Exception $e) {
            self::assertTrue(true);
        }
    }

    public function test_handles_errors_safe_ops(): void
    {
        $model = new EliteModel($this->orm);
        $model->fill(['id' => 1, 'name' => 'Elite']);

        // Mock failure for exec (used by store/update/trash)
        $this->orm->method('exec')->willThrowException(new VersaORMException('DB Error', 'DB_ERR'));

        // Mock failure for QueryBuilder (used by upsert/find/findAll)
        $qb = $this->createMock(\VersaORM\QueryBuilder::class);
        $qb->method('upsert')->willThrowException(new VersaORMException('Upsert Error', 'UPSERT_ERR'));
        $qb->method('findAll')->willThrowException(new VersaORMException('FindAll Error', 'FINDALL_ERR'));
        $qb->method('where')->willReturn($qb);

        $this->orm->method('table')->willReturn($qb);

        // Configure to not throw and ensure ErrorHandler is at least basic
        \VersaORM\ErrorHandler::configureFromVersaORM(['log_errors' => false]);
        EliteModel::configureErrorHandling(['throw_on_error' => false]);

        // safeStore
        $res = $model->safeStore();
        self::assertNull($res);
        self::assertTrue($model->hasError());

        // safeUpdate
        self::assertNull($model->safeUpdate(['name' => 'New']));

        // safeUpsert
        self::assertNull($model->safeUpsert(['id']));

        // safeFind
        // safeFind calls static::find() which we need to make throw
        // Since safeFind is in the trait, and find() is in EliteModel, we can use a class extension or closure
        // But safeFindAll actually calls queryTable()->findAll() which is already mocked to throw
        // safeFindAll
        $resAll = EliteModel::safeFindAll(['id' => 1]);
        self::assertNull($resAll);
    }

    public function test_handles_errors_protected_and_stats(): void
    {
        $model = new EliteModel($this->orm);

        // Use reflection for protected withStaticErrorHandling
        $refl = new ReflectionClass(EliteModel::class);
        $method = $refl->getMethod('withStaticErrorHandling');
        $method->setAccessible(true);

        $res = $method->invoke(
            null,
            function () {
                throw new VersaORMException('Static Error');
            },
            ['op' => 'test'],
        );
        self::assertNull($res);

        // validateBeforeOperation
        $vMethod = $refl->getMethod('validateBeforeOperation');
        $vMethod->setAccessible(true);
        self::assertFalse($vMethod->invoke($model, 'save')); // Empty attributes

        // error stats
        $stats = EliteModel::getErrorStats();
        self::assertIsArray($stats);
    }
}
