<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use DateTimeInterface;
use VersaORM\VersaModel;

use function get_class;

require_once __DIR__ . '/TestCase.php';
/**
 * @group mysql
 */
class DateTimeCastingConsistencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::$orm->exec('DROP TABLE IF EXISTS posts_dt_cast');
        self::$orm->schemaCreate('posts_dt_cast', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'title', 'type' => 'VARCHAR(100)', 'nullable' => false],
            ['name' => 'published_at', 'type' => 'DATETIME', 'nullable' => true],
        ]);
        self::$orm->table('posts_dt_cast')->insert(['title' => 'P1', 'published_at' => '2024-01-01 12:34:56']);
        self::$orm->table('posts_dt_cast')->insert(['title' => 'P2', 'published_at' => null]);
    }

    public function test_date_time_casting_consistent(): void
    {
        $model = new class('posts_dt_cast', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id' => ['type' => 'int'],
                    'title' => ['type' => 'string'],
                    'published_at' => ['type' => 'datetime', 'nullable' => true],
                ];
            }
        };

        $rows = self::$orm->table('posts_dt_cast', get_class($model))->get();
        static::assertCount(2, $rows);

        foreach ($rows as $r) {
            if ($r['published_at'] !== null) {
                static::assertInstanceOf(DateTimeInterface::class, $r['published_at']);
            }
        }

        $first = self::$orm->table('posts_dt_cast', get_class($model))->firstArray();

        if ($first && $first['published_at'] !== null) {
            static::assertInstanceOf(DateTimeInterface::class, $first['published_at']);
        }

        $objects = self::$orm->table('posts_dt_cast', get_class($model))->findAll();

        foreach ($objects as $o) {
            $data = $o->export();

            if ($data['published_at'] !== null) {
                static::assertInstanceOf(DateTimeInterface::class, $data['published_at']);
            }
        }

        $one = self::$orm->table('posts_dt_cast', get_class($model))->where('title', '=', 'P1')->findOne();
        static::assertNotNull($one);
        static::assertInstanceOf(DateTimeInterface::class, $one->export()['published_at']);
    }
}
