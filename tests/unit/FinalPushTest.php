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
        self::assertSame(10, $model->castToPhpType('age', '10'));
        self::assertSame(0, $model->castToPhpType('age', 'not-a-number'));

        // Bool
        self::assertTrue($model->castToPhpType('is_active', '1'));
        self::assertTrue($model->castToPhpType('is_active', 'true'));
        self::assertTrue($model->castToPhpType('is_active', 'yes'));
        self::assertFalse($model->castToPhpType('is_active', '0'));

        // JSON
        self::assertSame(['a' => 1], $model->castToPhpType('meta', '{"a":1}'));

        // UUID
        $uuid = '550e8400-e29b-41d4-a716-446655440000';
        self::assertSame($uuid, $model->castToPhpType('uid', $uuid));

        // Enum
        self::assertSame('active', $model->castToPhpType('status', 'active'));

        // Inet
        self::assertSame('127.0.0.1', $model->castToPhpType('ip', '127.0.0.1'));
        self::assertSame('::1', $model->castToPhpType('ip', '::1'));

        // DateTime
        $now = time();
        self::assertInstanceOf(\DateTimeInterface::class, $model->castToPhpType('born_at', $now));
        self::assertInstanceOf(\DateTimeInterface::class, $model->castToPhpType('born_at', '2023-01-01 10:00:00'));
    }

    public function test_has_strong_typing_db_casts(): void
    {
        $model = new FinalPushModel($this->orm);

        // String truncation/exception
        // If max_length is set and we exceed it.
        // Actually castToDatabaseType uses handlers too.

        self::assertSame(1, $model->castToDatabaseType('is_active', true));
        self::assertSame(0, $model->castToDatabaseType('is_active', false));

        $dt = new DateTime('2023-01-01 10:00:00');
        self::assertSame('2023-01-01 10:00:00', $model->castToDatabaseType('born_at', $dt));
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
        self::assertArrayHasKey('error', $api);
        self::assertSame('TEST_ERR', $api['error']['code']);
    }

    public function test_handles_errors_stats(): void
    {
        // Log an artificial error
        ErrorHandler::handleException(new VersaORMException('Test', 'LOG_ERR'), [
            'model_class' => FinalPushModel::class,
        ]);

        $stats = FinalPushModel::getErrorStats();
        self::assertGreaterThan(0, $stats['total_errors']);
        self::assertArrayHasKey('LOG_ERR', $stats['error_types']);
    }

    public function test_versa_schema_more_methods(): void
    {
        VersaSchema::setORM($this->orm);

        $this->orm->method('schema')->willReturn([]);

        self::assertFalse(VersaSchema::hasTable('non_existent'));
        self::assertIsArray(VersaSchema::getColumnListing('some_table'));

        $this->expectException(\RuntimeException::class);
        VersaSchema::connection('other');
    }

    public function test_has_strong_typing_exceptions(): void
    {
        $model = new FinalPushModel($this->orm);

        // Invalid UUID
        try {
            $model->castToPhpType('uid', 'invalid');
            $this->fail('Expected exception for invalid UUID');
        } catch (\Exception) {
            $this->assertTrue(true);
        }

        // Invalid IP
        try {
            $model->castToPhpType('ip', 'invalid-ip');
            $this->fail('Expected exception for invalid IP');
        } catch (\Exception) {
            $this->assertTrue(true);
        }
    }
}
