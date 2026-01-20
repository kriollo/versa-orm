<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\SQL\SqlGenerator;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

// Minimal test models to exercise relations in QueryBuilder tests
class TestPost extends VersaModel
{
    protected string $table = 'posts';

    public function tags()
    {
        return $this->belongsToMany(TestTag::class, 'post_tag', 'post_id', 'tag_id', 'id', 'id');
    }
}

class TestTag extends VersaModel
{
    protected string $table = 'tags';
}

class QueryBuilderExtraTest extends TestCase
{
    private static VersaORM $orm;

    public static function setUpBeforeClass(): void
    {
        // Minimal ORM config using sqlite memory for fast unit tests
        self::$orm = new VersaORM([
            'engine' => 'pdo',
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]);

        VersaModel::setORM(self::$orm);

        // create minimal table for tests
        self::$orm->exec('CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, body TEXT);');
        self::$orm->exec('CREATE TABLE tags (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);');
        self::$orm->exec('CREATE TABLE post_tag (post_id INTEGER, tag_id INTEGER);');
    }

    public function testBelongsToManyWithLoadsRelation()
    {
        // Dispense and store a post and a tag and attach via pivot
        $post = VersaModel::dispense('posts');
        $post->title = 'Hello';
        $postId = $post->store();

        $tag = VersaModel::dispense('tags');
        $tag->name = 'news';
        $tagId = $tag->store();

        // insert pivot
        self::$orm->exec('INSERT INTO post_tag (post_id, tag_id) VALUES (?, ?)', [$postId, $tagId]);

        // Build a query builder to fetch posts with tags via with (simulate relation)
        // Pass the model class so with() can resolve relation methods
        // Usar findAll para obtener instancias de modelo con relaciones cargadas
        $models = self::$orm->table('posts', TestPost::class)->where('id', '=', $postId)->with('tags')->findAll();

        static::assertIsArray($models);
        static::assertCount(1, $models);
        $firstModel = $models[0];
        static::assertInstanceOf(TestPost::class, $firstModel);
        // Verificar que la relación fue cargada y es un array
        $rel = $firstModel->getRelationValue('tags');
        static::assertIsArray($rel);
    }

    public function testInsertOrUpdateUpsertManyReplaceIntoScenarios()
    {
        // upsertMany via SqlGenerator compileBatch (use SQLite dialect instance)
        $params = [
            'table' => 'posts',
            'records' => [['title' => 'A', 'body' => 'x'], ['title' => 'B', 'body' => 'y']],
            'unique_keys' => ['id'],
        ];
        $generator = new ReflectionClass(\VersaORM\SQL\SqlGenerator::class);
        $method = $generator->getMethod('compileBatch');
        $method->setAccessible(true);
        // Crear dialecto SQLite para compilación estática
        $dialect = new \VersaORM\SQL\Dialects\SQLiteDialect();
        [$sql, $bindings] = $method->invoke(null, 'upsertMany', $params, $dialect);

        static::assertIsString($sql);
        static::assertIsArray($bindings);
        static::assertStringContainsString('INSERT INTO', strtoupper($sql));
    }

    public function testCollectChainExplainAndLazyOperations()
    {
        $qb = self::$orm->table('posts');
        // create several posts
        for ($i = 0; $i < 3; $i++) {
            $p = VersaModel::dispense('posts');
            $p->title = 't' . $i;
            $p->store();
        }

        $collected = $qb->collect();
        static::assertIsArray($collected);

        // chain and explain are higher-level behaviors; ensure methods exist and return expected shapes
        // chain requires another QueryBuilder instance as parameter
        $other = self::$orm->table('posts')->limit(1);
        $chain = $qb->chain($other);
        static::assertInstanceOf(\VersaORM\QueryBuilder::class, $chain);

        $explain = $qb->explain();
        static::assertIsArray($explain);
    }

    public function testWindowFunctionsAndCTEJsonArrayOps()
    {
        $qb = self::$orm->table('posts');
        // basic window function example (use correct method name and args)
        $res = $qb->windowFunction('row_number', '*', [], ['title'], [['title', 'ASC']], 'rn');
        static::assertIsArray($res);
        // withCte expects an array of ctes and a main query string
        $cteDefs = ['cte_test' => ['query' => 'SELECT id FROM posts', 'bindings' => []]];
        $cte = $qb->withCte($cteDefs, 'SELECT id FROM posts');
        static::assertIsArray($cte);

        // jsonOperation signature: (operation, column, path, value)
        $jsonOp = $qb->jsonOperation('array_length', 'body');
        static::assertIsArray($jsonOp);

        // arrayOperations signature: (operation, column, value)
        // Esta operación es específica de PostgreSQL; en otros drivers debe lanzar excepción.
        $driver = getenv('DB_DRIVER') ?: $_SERVER['DB_DRIVER'] ?? 'sqlite';
        if ($driver === 'postgresql') {
            $arrOps = $qb->arrayOperations('length', 'body');
            static::assertIsArray($arrOps);
        } else {
            $this->expectException(\VersaORM\VersaORMException::class);
            $qb->arrayOperations('length', 'body');
        }
    }

    public function testAdvancedQueryFeatures()
    {
        $qb = self::$orm->table('posts');
        $hints = $qb->queryHints(['no_cache' => true]);
        static::assertInstanceOf(\VersaORM\QueryBuilder::class, $hints);

        $ft = $qb->fullTextSearch(['title'], 'hello');
        static::assertIsArray($ft);

        $agg = $qb->advancedAggregation('group_concat', 'title');
        static::assertIsArray($agg);

        // Pasar una opción válida para evitar la excepción por query vacía
        $opt = $qb->optimizeQuery(['enable_join_optimization' => true]);
        static::assertIsArray($opt);

        $limits = $qb->getDriverLimits();
        static::assertIsArray($limits);
    }
}
