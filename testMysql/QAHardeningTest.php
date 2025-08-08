<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

/**
 * Pruebas duras estilo QA para romper el SqlGenerator y PdoEngine.
 */
class QAHardeningTest extends TestCase
{
    private VersaORM $orm;

    protected function setUp(): void
    {
        $config = [
            'engine' => 'pdo',
            'driver' => 'mysql',
            'host' => 'localhost',
            'port' => 3306,
            'database' => 'versaorm_test',
            'username' => 'local',
            'password' => 'local',
        ];
        $this->orm = new VersaORM($config);

        // Tablas con identificadores problemáticos
        $this->orm->exec('DROP TABLE IF EXISTS `order`;');
        $this->orm->exec('CREATE TABLE `order` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `select` VARCHAR(100),
            `group` VARCHAR(100),
            `name` VARCHAR(100) NOT NULL
        ) ENGINE=InnoDB;');
        $this->orm->table('order')->insert(['select' => 's1', 'group' => 'g1', 'name' => 'n1']);

        // Tabla para FULLTEXT y JSON
        $this->orm->exec('DROP TABLE IF EXISTS qa_docs;');
        $this->orm->exec('CREATE TABLE qa_docs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255),
            body TEXT,
            meta JSON,
            FULLTEXT(title, body)
        ) ENGINE=InnoDB;');
        $this->orm->table('qa_docs')->insert([
            'title' => 'Foo',
            'body' => 'lorem ipsum foo bar',
            'meta' => '{"tags":["a","b"]}',
        ]);
        $this->orm->table('qa_docs')->insert([
            'title' => 'Bar',
            'body' => 'foo boolean -bar +baz',
            'meta' => '{"tags":["b"]}',
        ]);
    }

    protected function tearDown(): void
    {
        $this->orm->exec('DROP TABLE IF EXISTS `order`;');
        $this->orm->exec('DROP TABLE IF EXISTS qa_docs;');
    }

    public function testReservedIdentifiersAreQuoted(): void
    {
        $qb = new QueryBuilder($this->orm, 'order');
        $rows = $qb->select(['select'])->where('group', '=', 'g1')->get();
        $this->assertNotEmpty($rows);
        $this->assertSame('s1', $rows[0]['select'] ?? null);
    }

    public function testWindowFunctionQualificationAndAlias(): void
    {
        $this->orm->table('order')->insert(['select' => 's2', 'group' => 'g1', 'name' => 'n2']);
        $this->orm->table('order')->insert(['select' => 's3', 'group' => 'g1', 'name' => 'n3']);
        $qb = new QueryBuilder($this->orm, 'order');
        $rows = $qb->windowFunction('row_number', '*', [], ['group'], [['column' => 'name', 'direction' => 'ASC']], 'rn');
        $this->assertNotEmpty($rows);
        $this->assertArrayHasKey('rn', $rows[0]);
    }

    public function testFullTextSearchBooleanModeWithScore(): void
    {
        $qb = new QueryBuilder($this->orm, 'qa_docs');
        // Usar una consulta que garantice coincidencias (exigir "foo" y excluir "baz")
        $rows = $qb->fullTextSearch(['title', 'body'], '"foo" -baz', ['mode' => 'BOOLEAN', 'with_score' => true]);
        $this->assertIsArray($rows);
        // score debe existir cuando with_score es true
        $this->assertArrayHasKey('score', $rows[0] ?? []);
    }

    public function testCteWithBindings(): void
    {
        $qb = new QueryBuilder($this->orm, 'qa_docs');
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
        $qb = new QueryBuilder($this->orm, 'qa_docs');
        $rows = $qb->advancedAggregation('group_concat', 'title', ['separator' => "'|,|'", 'order_by' => 'id ASC']);
        $this->assertIsArray($rows);
        $this->assertArrayHasKey('agg', $rows[0] ?? []);
    }
}
