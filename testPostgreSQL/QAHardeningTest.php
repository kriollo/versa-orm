<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\QueryBuilder;

/**
 * Pruebas duras estilo QA para romper el SqlGenerator y PdoEngine.
 */
class QAHardeningTest extends TestCase
{
    protected function setUp(): void
    {
        $driver = self::$orm->getConfig()['driver'] ?? '';
        if ($driver !== 'mysql') {
            $this->markTestSkipped('QAHardeningTest es específico de MySQL; omitido en suite PostgreSQL');
        }

        // Tablas con identificadores problemáticos
        self::$orm->exec('DROP TABLE IF EXISTS `order`;');
        self::$orm->exec('CREATE TABLE `order` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `select` VARCHAR(100),
            `group` VARCHAR(100),
            `name` VARCHAR(100) NOT NULL
        ) ENGINE=InnoDB;');
        self::$orm->table('order')->insert(['select' => 's1', 'group' => 'g1', 'name' => 'n1']);

        // Tabla para FULLTEXT y JSON
        self::$orm->exec('DROP TABLE IF EXISTS qa_docs;');
        self::$orm->exec('CREATE TABLE qa_docs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255),
            body TEXT,
            meta JSON,
            FULLTEXT(title, body)
        ) ENGINE=InnoDB;');
        self::$orm->table('qa_docs')->insert([
            'title' => 'Foo',
            'body' => 'lorem ipsum foo bar',
            'meta' => '{"tags":["a","b"]}',
        ]);
        self::$orm->table('qa_docs')->insert([
            'title' => 'Bar',
            'body' => 'foo boolean -bar +baz',
            'meta' => '{"tags":["b"]}',
        ]);
    }

    protected function tearDown(): void
    {
        try {
            self::$orm->exec('DROP TABLE IF EXISTS `order`;');
        } catch (\Throwable $e) {
        }
        try {
            self::$orm->exec('DROP TABLE IF EXISTS qa_docs;');
        } catch (\Throwable $e) {
        }
    }

    public function testReservedIdentifiersAreQuoted(): void
    {
        $qb = new QueryBuilder(self::$orm, 'order');
        $rows = $qb->select(['select'])->where('group', '=', 'g1')->get();
        $this->assertNotEmpty($rows);
        $this->assertSame('s1', $rows[0]['select'] ?? null);
    }

    public function testWindowFunctionQualificationAndAlias(): void
    {
        self::$orm->table('order')->insert(['select' => 's2', 'group' => 'g1', 'name' => 'n2']);
        self::$orm->table('order')->insert(['select' => 's3', 'group' => 'g1', 'name' => 'n3']);
        $qb = new QueryBuilder(self::$orm, 'order');
        $rows = $qb->windowFunction('row_number', '*', [], ['group'], [['column' => 'name', 'direction' => 'ASC']], 'rn');
        $this->assertNotEmpty($rows);
        $this->assertArrayHasKey('rn', $rows[0]);
    }

    public function testFullTextSearchBooleanModeWithScore(): void
    {
        $qb = new QueryBuilder(self::$orm, 'qa_docs');
        // Usar una consulta que garantice coincidencias (exigir "foo" y excluir "baz")
        $rows = $qb->fullTextSearch(['title', 'body'], '"foo" -baz', ['mode' => 'BOOLEAN', 'with_score' => true]);
        $this->assertIsArray($rows);
        // score debe existir cuando with_score es true
        $this->assertArrayHasKey('score', $rows[0] ?? []);
    }

    public function testCteWithBindings(): void
    {
        $qb = new QueryBuilder(self::$orm, 'qa_docs');
        $rows = $qb->withCte([
            'docs' => [
                'query' => 'SELECT id, title FROM qa_docs WHERE id > ?',
                'bindings' => [0]
            ]
        ], 'SELECT * FROM docs WHERE title LIKE ?', ['%o%']);
        $this->assertNotEmpty($rows);
    }

    public function testGroupConcatWithSpecialSeparator(): void
    {
        $qb = new QueryBuilder(self::$orm, 'qa_docs');
        $rows = $qb->advancedAggregation('group_concat', 'title', ['separator' => "'|,|'", 'order_by' => 'id ASC']);
        $this->assertIsArray($rows);
        $this->assertArrayHasKey('agg', $rows[0] ?? []);
    }
}
