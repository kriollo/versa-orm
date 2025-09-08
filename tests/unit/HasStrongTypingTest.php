<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\Traits\HasStrongTyping;

/**
 * @group sqlite
 */
final class HasStrongTypingTest extends TestCase
{
    public function testGetPropertyTypesAndNormalization(): void
    {
        $types = TestStrongModel::getPropertyTypes();

        self::assertArrayHasKey('age', $types);
        self::assertSame('int', $types['age']['type']);
        self::assertArrayHasKey('price', $types);
        self::assertSame('decimal', $types['price']['type']);
    }

    public function testCastToPhpTypeHandlesVariousTypes(): void
    {
        $m = new TestStrongModel();

        $meta = $m->castToPhpType('meta', '{"a":1}');
        self::assertIsArray($meta);
        self::assertSame(1, $meta['a']);

        $dt = $m->castToPhpType('created', '2020-01-01 00:00:00');
        self::assertInstanceOf(DateTimeInterface::class, $dt);

        $age = $m->castToPhpType('age', '42');
        self::assertSame(42, $age);

        $flag = $m->castToPhpType('flag', 'true');
        self::assertTrue($flag);

        $arr = $m->castToPhpType('list', 'a,b,c');
        self::assertIsArray($arr);
    }

    public function testCastToDatabaseTypeConvertsProperly(): void
    {
        $m = new TestStrongModel();

        $dtStr = $m->castToDatabaseType('created', new DateTime('2020-01-01 00:00:00'));
        self::assertIsString($dtStr);

        $boolDb = $m->castToDatabaseType('flag', true);
        self::assertSame(1, $boolDb);

        $jsonDb = $m->castToDatabaseType('meta', ['x' => 2]);
        self::assertIsString($jsonDb);

        $setDb = $m->castToDatabaseType('tags', ['a', 'b']);
        self::assertIsString($setDb);
        self::assertStringContainsString('a', $setDb);
    }

    public function testAddAndRemoveTypeConverter(): void
    {
        $m = new TestStrongModel();

        // Ensure salary property uses default behavior first
        $orig = $m->castToPhpType('salary', '100');
        self::assertSame('100', $orig);

        // Register custom converter
        TestStrongModel::addTypeConverter(
            'money',
            static fn($s, $p, $v, $_ = []) => (int) $v,
            static fn($s, $p, $v, $_ = []) => 'DB:' . (string) $v,
        );

        // Now salary type 'money' should use converter
        $val = $m->castToPhpType('salary', '100');
        self::assertSame(100, $val);

        $db = $m->castToDatabaseType('salary', 100);
        self::assertSame('DB:100', $db);

        // Remove converter
        TestStrongModel::removeTypeConverter('money');

        $after = $m->castToPhpType('salary', '100');
        self::assertSame('100', $after);
    }
}

if (!class_exists('TestStrongModel')) {
    class TestStrongModel
    {
        use HasStrongTyping;

        public static function propertyTypes(): array
        {
            return [
                'age' => ['type' => 'int'],
                'price' => ['type' => 'decimal'],
                'meta' => ['type' => 'json'],
                'created' => ['type' => 'datetime'],
                'flag' => ['type' => 'boolean'],
                'tags' => ['type' => 'set', 'values' => ['a', 'b', 'c']],
                'status' => ['type' => 'enum', 'values' => ['ok', 'pending']],
                'ips' => ['type' => 'inet'],
                'ident' => ['type' => 'uuid'],
                'list' => ['type' => 'array'],
                // salary uses custom type 'money' for converter test
                'salary' => ['type' => 'money'],
            ];
        }
    }
}
