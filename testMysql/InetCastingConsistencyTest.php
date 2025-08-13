<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\VersaModel;

use function get_class;

require_once __DIR__ . '/TestCase.php';
/**
 * @group mysql
 */
class InetCastingConsistencyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::$orm->exec('DROP TABLE IF EXISTS access_logs_inet_cast');
        self::$orm->schemaCreate('access_logs_inet_cast', [
            ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'ip_address', 'type' => 'VARCHAR(45)', 'nullable' => false],
        ]);
        self::$orm->table('access_logs_inet_cast')->insert(['ip_address' => '2001:0db8:85a3:0000:0000:8a2e:0370:7334']);
    }

    public function testInetCastingConsistency(): void
    {
        $model = new class('access_logs_inet_cast', self::$orm) extends VersaModel {
            protected static function definePropertyTypes(): array
            {
                return [
                    'id'         => ['type' => 'int'],
                    'ip_address' => ['type' => 'inet'],
                ];
            }
        };

        $rows = self::$orm->table('access_logs_inet_cast', get_class($model))->get();
        self::assertCount(1, $rows);
        self::assertSame('2001:db8:85a3::8a2e:370:7334', $rows[0]['ip_address']);

        $first = self::$orm->table('access_logs_inet_cast', get_class($model))->firstArray();
        self::assertNotNull($first);
        self::assertSame('2001:db8:85a3::8a2e:370:7334', $first['ip_address']);

        $objects = self::$orm->table('access_logs_inet_cast', get_class($model))->findAll();
        self::assertSame('2001:db8:85a3::8a2e:370:7334', $objects[0]->export()['ip_address']);

        $one = self::$orm->table('access_logs_inet_cast', get_class($model))->where('id', '=', 1)->findOne();
        self::assertNotNull($one);
        self::assertSame('2001:db8:85a3::8a2e:370:7334', $one->export()['ip_address']);
    }
}
