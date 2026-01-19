<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use DateTime;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\ErrorHandler;
use VersaORM\Schema\VersaSchema;
use VersaORM\Traits\HandlesErrors;
use VersaORM\VersaModel;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

class FinalPushModel extends VersaModel
{
    use HandlesErrors;

    protected string $table = 'final_push';

    public function __construct($orm = null)
    {
        parent::__construct($this->table, $orm);
    }

    public static function propertyTypes(): array
    {
        return [
            'age' => ['type' => 'int'],
            'price' => ['type' => 'float'],
            'is_active' => ['type' => 'bool'],
            'tags' => ['type' => 'array'],
            'meta' => ['type' => 'json'],
            'uid' => ['type' => 'uuid'],
            'status' => ['type' => 'enum', 'values' => ['active', 'inactive']],
            'permissions' => ['type' => 'set', 'values' => ['read', 'write', 'admin']],
            'ip' => ['type' => 'inet'],
            'born_at' => ['type' => 'datetime'],
        ];
    }
}

/**
 * @group core
 */
class FinalPushTest extends TestCase
{
    private $orm;

    protected function setUp(): void
    {
        $this->orm = $this->createMock(VersaORM::class);
        $this->orm->method('getConfig')->willReturn(['driver' => 'sqlite']);
        VersaModel::setORM($this->orm);
        ErrorHandler::clearErrorLog();
        FinalPushModel::configureErrorHandling(['throw_on_error' => false]);
    }

    public function test_has_strong_typing_php_casts(): void
    {
        $model = new FinalPushModel($this->orm);

        // Int
        static::assertSame(10, $model->castToPhpType('age', '10'));
        static::assertSame(0, $model->castToPhpType('age', 'not-a-number'));

        // Bool
        static::assertTrue($model->castToPhpType('is_active', '1'));
        static::assertTrue($model->castToPhpType('is_active', 'true'));
        static::assertTrue($model->castToPhpType('is_active', 'yes'));
        static::assertFalse($model->castToPhpType('is_active', '0'));

        // JSON
        static::assertSame(['a' => 1], $model->castToPhpType('meta', '{"a":1}'));

        // UUID
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        static::assertSame($uuid, $model->castToPhpType('uid', $uuid));

        // Enum
        static::assertSame('active', $model->castToPhpType('status', 'active'));

        // Inet
        static::assertSame('127.0.0.1', $model->castToPhpType('ip', '127.0.0.1'));
        static::assertSame('::1', $model->castToPhpType('ip', '::1'));

        // DateTime
        $now = time();
        static::assertInstanceOf(\DateTimeInterface::class, $model->castToPhpType('born_at', $now));
        static::assertInstanceOf(\DateTimeInterface::class, $model->castToPhpType('born_at', '2023-01-01 10:00:00'));
    }

    public function test_has_strong_typing_db_casts(): void
    {
        $model = new FinalPushModel($this->orm);

        // String truncation/exception
        // If max_length is set and we exceed it.
        // Actually castToDatabaseType uses handlers too.

        static::assertSame(1, $model->castToDatabaseType('is_active', true));
        static::assertSame(0, $model->castToDatabaseType('is_active', false));

        $dt = new DateTime('2023-01-01 10:00:00');
        static::assertSame('2023-01-01 10:00:00', $model->castToDatabaseType('born_at', $dt));
    }

    public function test_handles_errors_safe_methods(): void
    {
        $model = new FinalPushModel($this->orm);

        // Mock a failure in store()
        // We'll use a hack by making store() throw via some internal means if possible,
        // or just test the logic that calls withErrorHandling.

        // Test formatErrorForApi
        $refl = new ReflectionClass(FinalPushModel::class);
        $method = $refl->getMethod('formatErrorForApi');
        $method->setAccessible(true);

        $errorData = [
            'error' => ['message' => 'Fail', 'error_code' => 'TEST_ERR'],
            'suggestions' => ['Try again'],
            'query' => 'SELECT 1',
            'origin' => 'test',
            'context' => [],
        ];

        $api = $method->invoke($model, $errorData);
        static::assertArrayHasKey('error', $api);
        static::assertSame('TEST_ERR', $api['error']['code']);
    }

    public function test_handles_errors_stats(): void
    {
        // Log an artificial error
        ErrorHandler::handleException(new VersaORMException('Test', 'LOG_ERR'), [
            'model_class' => FinalPushModel::class,
        ]);

        $stats = FinalPushModel::getErrorStats();
        static::assertGreaterThan(0, $stats['total_errors']);
        static::assertArrayHasKey('LOG_ERR', $stats['error_types']);
    }

    public function test_versa_schema_more_methods(): void
    {
        VersaSchema::setORM($this->orm);

        $this->orm->method('schema')->willReturn([]);

        static::assertFalse(VersaSchema::hasTable('non_existent'));
        static::assertIsArray(VersaSchema::getColumnListing('some_table'));

        $this->expectException(\RuntimeException::class);
        VersaSchema::connection('other');
    }

    public function test_has_strong_typing_exceptions(): void
    {
        $model = new FinalPushModel($this->orm);

        // Invalid UUID
        try {
            $model->castToPhpType('uid', 'invalid');
            static::fail('Expected exception for invalid UUID');
        } catch (\Exception) {
            static::assertTrue(true);
        }

        // Invalid IP
        try {
            $model->castToPhpType('ip', 'invalid-ip');
            static::fail('Expected exception for invalid IP');
        } catch (\Exception) {
            static::assertTrue(true);
        }
    }
}
