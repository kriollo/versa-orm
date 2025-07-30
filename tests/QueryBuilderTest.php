<?php

// tests/QueryBuilderTest.php

declare(strict_types=1);

namespace VersaORM\Tests;

class QueryBuilderTest extends TestCase
{
    //======================================================================
    // SELECT and GET Methods
    //======================================================================

    public function testGetAll(): void
    {
        $users = self::$orm->table('users')->getAll();
        $this->assertCount(3, $users);
        $this->assertIsArray($users[0]);
        $this->assertArrayHasKey('email', $users[0]);
    }

    public function testFindAll(): void
    {
        $users = self::$orm->table('users')->findAll();
        $this->assertCount(3, $users);
        $this->assertInstanceOf(\VersaORM\VersaModel::class, $users[0]);
        $this->assertEquals('alice@example.com', $users[0]->email);
    }

    public function testSelectSpecificColumns(): void
    {
        $user = self::$orm->table('users')->select(['id', 'name'])->where('email', '=', 'alice@example.com')->firstArray();
        $this->assertCount(2, $user);
        $this->assertArrayHasKey('id', $user);
        $this->assertArrayHasKey('name', $user);
        $this->assertArrayNotHasKey('email', $user);
    }

    public function testFirstArray(): void
    {
        $user = self::$orm->table('users')->where('status', '=', 'active')->orderBy('id', 'asc')->firstArray();
        $this->assertIsArray($user);
        $this->assertEquals('Alice', $user['name']);
    }

    public function testFindOne(): void
    {
        $user = self::$orm->table('users')->where('status', '=', 'active')->orderBy('id', 'asc')->findOne();
        $this->assertInstanceOf(\VersaORM\VersaModel::class, $user);
        $this->assertEquals('Alice', $user->name);
    }

    public function testFind(): void
    {
        $user = self::$orm->table('users')->find(1);
        $this->assertInstanceOf(\VersaORM\VersaModel::class, $user);
        $this->assertEquals('Alice', $user->name);
    }

    public function testFindWithCustomPk(): void
    {
        $product = self::$orm->table('products')->find('P001', 'sku');
        $this->assertInstanceOf(\VersaORM\VersaModel::class, $product);
        $this->assertEquals('Laptop', $product->name);
    }

    public function testCount(): void
    {
        $count = self::$orm->table('users')->where('status', '=', 'active')->count();
        $this->assertEquals(2, $count);
    }

    public function testExists(): void
    {
        $exists = self::$orm->table('users')->where('email', '=', 'bob@example.com')->exists();
        $this->assertTrue($exists);

        $doesNotExist = self::$orm->table('users')->where('email', '=', 'nobody@example.com')->exists();
        $this->assertFalse($doesNotExist);
    }

    //======================================================================
    // WHERE Clauses
    //======================================================================

    public function testWhere(): void
    {
        $users = self::$orm->table('users')->where('status', '=', 'inactive')->findAll();
        $this->assertCount(1, $users);
        $this->assertEquals('Bob', $users[0]->name);
    }

    public function testWhereGreaterThan(): void
    {
        $users = self::$orm->table('users')->where('id', '>', 1)->findAll();
        $this->assertCount(2, $users);
    }

    public function testOrWhere(): void
    {
        $users = self::$orm->table('users')->where('status', '=', 'inactive')->orWhere('id', '=', 3)->findAll();
        $this->assertCount(2, $users);
    }

    public function testWhereInDebug(): void
    {
        // Create a separate ORM instance to avoid setup data being inserted
        global $config;
        $orm = new \VersaORM\VersaORM([
            'driver' => $config['DB']['DB_DRIVER'],
            'host' => $config['DB']['DB_HOST'],
            'port' => $config['DB']['DB_PORT'],
            'database' => $config['DB']['DB_NAME'],
            'username' => $config['DB']['DB_USER'],
            'password' => $config['DB']['DB_PASS'],
            'debug' => true
        ]);

        $query = $orm->table('users')->whereIn('id', [1, 3]);
        // The query will be dumped and exit in execute method
        $users = $query->findAll();
        $this->assertCount(2, $users);
    }

    public function testWhereIn(): void
    {
        $query = self::$orm->table('users')->whereIn('id', [1, 3]);
        // The query will be dumped and exit in execute method
        $users = $query->findAll();
        $this->assertCount(2, $users);
    }

    public function testWhereNotIn(): void
    {
        $users = self::$orm->table('users')->whereNotIn('id', [1, 3])->findAll();
        $this->assertCount(1, $users);
        $this->assertEquals('Bob', $users[0]->name);
    }

    public function testWhereNull(): void
    {
        self::$orm->table('posts')->insert(['user_id' => 1, 'title' => 'Draft Post', 'content' => '...', 'published_at' => null]);
        $posts = self::$orm->table('posts')->whereNull('published_at')->findAll();
        $this->assertCount(4, $posts); // 3 from seed + 1 new
    }

    public function testWhereNotNull(): void
    {
        self::$orm->table('posts')->where('id', '=', 1)->update(['published_at' => date('Y-m-d H:i:s')]);
        $posts = self::$orm->table('posts')->whereNotNull('published_at')->findAll();
        $this->assertCount(1, $posts);
    }

    public function testWhereBetween(): void
    {
        $products = self::$orm->table('products')->whereBetween('price', 20, 30)->findAll();
        $this->assertCount(1, $products);
        $this->assertEquals('Mouse', $products[0]->name);
    }

    public function testWhereRaw(): void
    {
        $users = self::$orm->table('users')->whereRaw('LOWER(name) = ?', ['alice'])->findAll();
        $this->assertCount(1, $users);
        $this->assertEquals('Alice', $users[0]->name);
    }

    //======================================================================
    // JOIN Clauses
    //======================================================================

    public function testJoin(): void
    {
        $posts = self::$orm->table('posts')
            ->select(['posts.title', 'users.name as author'])
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->where('users.status', '=', 'active')
            ->getAll();

        $this->assertCount(2, $posts);
        $this->assertEquals('Alice', $posts[0]['author']);
    }

    public function testLeftJoin(): void
    {
        self::$orm->table('users')->insert(['name' => 'Eve', 'email' => 'eve@example.com']);
        $users = self::$orm->table('users')
            ->select(['users.name', 'posts.id as post_id'])
            ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
            ->whereNull('posts.id')
            ->getAll();

        $this->assertCount(2, $users); // Charlie and Eve have no posts
    }

    //======================================================================
    // Order, Group, Limit, Offset
    //======================================================================

    public function testOrderBy(): void
    {
        $users = self::$orm->table('users')->orderBy('name', 'desc')->findAll();
        $this->assertEquals('Charlie', $users[0]->name);
        $this->assertEquals('Bob', $users[1]->name);
        $this->assertEquals('Alice', $users[2]->name);
    }

    public function testLimit(): void
    {
        $users = self::$orm->table('users')->limit(2)->orderBy('id', 'asc')->findAll();
        $this->assertCount(2, $users);
        $this->assertEquals('Alice', $users[0]->name);
    }

    public function testOffset(): void
    {
        $users = self::$orm->table('users')->limit(1)->offset(1)->orderBy('id', 'asc')->findAll();
        $this->assertCount(1, $users);
        $this->assertEquals('Bob', $users[0]->name);
    }

    public function testGroupByAndHaving(): void
    {
        $this->markTestIncomplete('GROUP BY and HAVING functionality is not yet fully implemented in the QueryBuilder.');
    }

    //======================================================================
    // Write Operations (INSERT, UPDATE, DELETE)
    //======================================================================

    public function testInsert(): void
    {
        self::$orm->table('users')->insert([
            'name' => 'Frank',
            'email' => 'frank@example.com',
            'status' => 'active'
        ]);

        $frank = self::$orm->table('users')->where('email', '=', 'frank@example.com')->findOne();
        $this->assertNotNull($frank);
        $this->assertEquals('Frank', $frank->name);
    }

    public function testInsertGetId(): void
    {
        $id = self::$orm->table('users')->insertGetId([
            'name' => 'Grace',
            'email' => 'grace@example.com',
            'status' => 'active'
        ]);

        $this->assertIsNumeric($id);
        $grace = self::$orm->table('users')->find($id);
        $this->assertEquals('Grace', $grace->name);
    }

    public function testUpdate(): void
    {
        $updated = self::$orm->table('users')
            ->where('email', '=', 'alice@example.com')
            ->update(['status' => 'on_vacation']);

        $this->assertInstanceOf(\VersaORM\QueryBuilder::class, $updated);

        $alice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        $this->assertEquals('on_vacation', $alice->status);
    }

    public function testDelete(): void
    {
        $deleted = self::$orm->table('users')
            ->where('email', '=', 'bob@example.com')
            ->delete();

        $this->assertInstanceOf(\VersaORM\QueryBuilder::class, $deleted);
        $bob = self::$orm->table('users')->where('email', '=', 'bob@example.com')->findOne();
        $this->assertNull($bob);
    }
}
