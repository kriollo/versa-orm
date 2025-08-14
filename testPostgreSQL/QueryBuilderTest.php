<?php

// tests/QueryBuilderTest.php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

class QueryBuilderTest extends TestCase
{
    // ======================================================================
    // SELECT and GET Methods
    // ======================================================================

    public function testGetAll(): void
    {
        $users = self::$orm->table('users')->getAll();
        self::assertCount(3, $users);
        self::assertIsArray($users[0]);
        self::assertArrayHasKey('email', $users[0]);
    }

    public function testFindAll(): void
    {
        $users = self::$orm->table('users')->findAll();
        self::assertCount(3, $users);
        self::assertInstanceOf(VersaModel::class, $users[0]);
        self::assertSame('alice@example.com', $users[0]->email);
    }

    public function testSelectSpecificColumns(): void
    {
        $user = self::$orm->table('users')->select(['id', 'name'])->where('email', '=', 'alice@example.com')->firstArray();
        self::assertCount(2, $user);
        self::assertArrayHasKey('id', $user);
        self::assertArrayHasKey('name', $user);
        self::assertArrayNotHasKey('email', $user);
    }

    public function testFirstArray(): void
    {
        $user = self::$orm->table('users')->where('status', '=', 'active')->orderBy('id', 'asc')->firstArray();
        self::assertIsArray($user);
        self::assertSame('Alice', $user['name']);
    }

    public function testFindOne(): void
    {
        $user = self::$orm->table('users')->where('status', '=', 'active')->orderBy('id', 'asc')->findOne();
        self::assertInstanceOf(VersaModel::class, $user);
        self::assertSame('Alice', $user->name);
    }

    public function testFind(): void
    {
        $user = self::$orm->table('users')->find(1);
        self::assertInstanceOf(VersaModel::class, $user);
        self::assertSame('Alice', $user->name);
    }

    public function testFindWithCustomPk(): void
    {
        $product = self::$orm->table('products')->find('P001', 'sku');
        self::assertInstanceOf(VersaModel::class, $product);
        self::assertSame('Laptop', $product->name);
    }

    public function testCount(): void
    {
        $count = self::$orm->table('users')->where('status', '=', 'active')->count();
        self::assertSame(2, $count);
    }

    public function testExists(): void
    {
        $exists = self::$orm->table('users')->where('email', '=', 'bob@example.com')->exists();
        self::assertTrue($exists);

        $doesNotExist = self::$orm->table('users')->where('email', '=', 'nobody@example.com')->exists();
        self::assertFalse($doesNotExist);
    }

    /** @only */
    public function testWhere(): void
    {
        $users = self::$orm->table('users')->where('status', '=', 'inactive')->findAll();
        self::assertCount(1, $users);
        self::assertSame('Bob', $users[0]->name);
    }

    public function testWhereGreaterThan(): void
    {
        $users = self::$orm->table('users')->where('id', '>', 1)->findAll();
        self::assertCount(2, $users);
    }

    public function testOrWhere(): void
    {
        $users = self::$orm->table('users')->where('status', '=', 'inactive')->orWhere('id', '=', 3)->findAll();
        self::assertCount(2, $users);
    }

    public function testWhereInDebug(): void
    {
        // Unificado: usar el ORM compartido del TestCase, sin crear configuración local
        $query = self::$orm->table('users')->whereIn('id', [1, 3]);
        $users = $query->findAll();
        self::assertCount(2, $users);
    }

    public function testWhereIn(): void
    {
        $query = self::$orm->table('users')->whereIn('id', [1, 3]);
        // The query will be dumped and exit in execute method
        $users = $query->findAll();
        self::assertCount(2, $users);
    }

    public function testWhereNotIn(): void
    {
        $users = self::$orm->table('users')->whereNotIn('id', [1, 3])->findAll();
        self::assertCount(1, $users);
        self::assertSame('Bob', $users[0]->name);
    }

    public function testWhereNull(): void
    {
        self::$orm->table('posts')->insert(['user_id' => 1, 'title' => 'Draft Post', 'content' => '...', 'published_at' => null]);
        $posts = self::$orm->table('posts')->whereNull('published_at')->findAll();
        self::assertCount(4, $posts); // 3 from seed + 1 new
    }

    public function testWhereNotNull(): void
    {
        self::$orm->table('posts')->where('id', '=', 1)->update(['published_at' => date('Y-m-d H:i:s')]);
        $posts = self::$orm->table('posts')->whereNotNull('published_at')->findAll();
        self::assertCount(1, $posts);
    }

    public function testWhereBetween(): void
    {
        $products = self::$orm->table('products')->whereBetween('price', 20, 30)->findAll();
        self::assertCount(1, $products);
        self::assertSame('Mouse', $products[0]->name);
    }

    public function testWhereRaw(): void
    {
        $users = self::$orm->table('users')->whereRaw('LOWER(name) = ?', ['alice'])->findAll();
        self::assertCount(1, $users);
        self::assertSame('Alice', $users[0]->name);
    }

    // ======================================================================
    // JOIN Clauses
    // ======================================================================

    public function testJoin(): void
    {
        $posts = self::$orm->table('posts')
            ->select(['posts.title', 'users.name as author'])
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->where('users.status', '=', 'active')
            ->getAll()
        ;

        self::assertCount(2, $posts);
        self::assertSame('Alice', $posts[0]['author']);
    }

    public function testLeftJoin(): void
    {
        self::$orm->table('users')->insert(['name' => 'Eve', 'email' => 'eve@example.com']);
        $users = self::$orm->table('users')
            ->select(['users.name', 'posts.id as post_id'])
            ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
            ->whereNull('posts.id')
            ->getAll()
        ;

        self::assertCount(2, $users); // Charlie and Eve have no posts
    }

    // ======================================================================
    // Order, Group, Limit, Offset
    // ======================================================================

    public function testOrderBy(): void
    {
        $users = self::$orm->table('users')->orderBy('name', 'desc')->findAll();
        self::assertSame('Charlie', $users[0]->name);
        self::assertSame('Bob', $users[1]->name);
        self::assertSame('Alice', $users[2]->name);
    }

    public function testLimit(): void
    {
        $users = self::$orm->table('users')->limit(2)->orderBy('id', 'asc')->findAll();
        self::assertCount(2, $users);
        self::assertSame('Alice', $users[0]->name);
    }

    public function testOffset(): void
    {
        $users = self::$orm->table('users')->limit(1)->offset(1)->orderBy('id', 'asc')->findAll();
        self::assertCount(1, $users);
        self::assertSame('Bob', $users[0]->name);
    }

    public function testGroupBy(): void
    {
        // Test simple groupBy
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as count'])
            ->groupBy('status')
            ->orderBy('status', 'asc')
            ->get()
        ;

        self::assertCount(2, $results);
        self::assertSame('active', $results[0]['status']);
        self::assertSame(2, $results[0]['count']);
        self::assertSame('inactive', $results[1]['status']);
        self::assertSame(1, $results[1]['count']);
    }

    public function testGroupByMultipleColumns(): void
    {
        // Test groupBy with multiple columns
        $results = self::$orm->table('posts')
            ->select(['user_id', 'COUNT(*) as post_count'])
            ->groupBy(['user_id'])
            ->orderBy('user_id', 'asc')
            ->get()
        ;

        self::assertCount(2, $results); // Alice has 2 posts, Bob has 1 post
        self::assertSame(1, $results[0]['user_id']);
        self::assertSame(2, $results[0]['post_count']);
        self::assertSame(2, $results[1]['user_id']);
        self::assertSame(1, $results[1]['post_count']);
    }

    public function testHaving(): void
    {
        // Test groupBy with having
        // En PostgreSQL, el alias en HAVING no siempre es reconocido; usar la expresión
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as count'])
            ->groupBy('status')
            ->having('COUNT(*)', '>', 1)
            ->get()
        ;

        self::assertCount(1, $results);
        self::assertSame('active', $results[0]['status']);
        self::assertSame(2, $results[0]['count']);
    }

    public function testHavingMultipleConditions(): void
    {
        // Test having with multiple conditions
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as count'])
            ->groupBy('status')
            ->having('COUNT(*)', '>=', 1)
            ->having('COUNT(*)', '<=', 2)
            ->orderBy('status', 'asc')
            ->get()
        ;

        self::assertCount(2, $results); // Both groups should match
        self::assertSame('active', $results[0]['status']);
        self::assertSame('inactive', $results[1]['status']);
    }

    // ======================================================================
    // Write Operations (INSERT, UPDATE, DELETE)
    // ======================================================================

    public function testInsert(): void
    {
        self::$orm->table('users')->insert([
            'name' => 'Frank',
            'email' => 'frank@example.com',
            'status' => 'active',
        ]);

        $frank = self::$orm->table('users')->where('email', '=', 'frank@example.com')->findOne();
        self::assertNotNull($frank);
        self::assertSame('Frank', $frank->name);
    }

    public function testInsertGetId(): void
    {
        $id = self::$orm->table('users')->insertGetId([
            'name' => 'Grace',
            'email' => 'grace@example.com',
            'status' => 'active',
        ]);

        // Verificar que el ID devuelto es un entero, no un string
        self::assertIsInt($id, 'insertGetId() should return an integer');
        self::assertGreaterThan(0, $id, 'insertGetId() should return a positive integer');

        // Verificar que el registro se insertó correctamente
        $grace = self::$orm->table('users')->find($id);
        self::assertNotNull($grace, 'Should be able to find the inserted record');
        self::assertSame('Grace', $grace->name);
    }

    public function testUpdate(): void
    {
        $updated = self::$orm->table('users')
            ->where('email', '=', 'alice@example.com')
            ->update(['status' => 'on_vacation'])
        ;

        self::assertInstanceOf(QueryBuilder::class, $updated);

        $alice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        self::assertSame('on_vacation', $alice->status);
    }

    public function testDelete(): void
    {
        $deleted = self::$orm->table('users')
            ->where('email', '=', 'bob@example.com')
            ->delete()
        ;

        self::assertNull($deleted);
        $bob = self::$orm->table('users')->where('email', '=', 'bob@example.com')->findOne();
        self::assertNull($bob);
    }
}
