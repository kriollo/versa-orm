<?php

// tests/QueryBuilderTest.php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

use function is_int;

/**
 * @group mysql
 */
class QueryBuilderTest extends TestCase
{
    // ======================================================================
    // SELECT and GET Methods
    // ======================================================================

    public function test_get_all(): void
    {
        $users = self::$orm->table('users')->getAll();
        self::assertCount(3, $users);
        self::assertIsArray($users[0]);
        self::assertArrayHasKey('email', $users[0]);
    }

    public function test_find_all(): void
    {
        $users = self::$orm->table('users')->findAll();
        self::assertCount(3, $users);
        self::assertInstanceOf(VersaModel::class, $users[0]);
        self::assertSame('alice@example.com', $users[0]->email);
    }

    public function test_select_specific_columns(): void
    {
        $user = self::$orm->table('users')->select(['id', 'name'])->where('email', '=', 'alice@example.com')->firstArray();
        self::assertCount(2, $user);
        self::assertArrayHasKey('id', $user);
        self::assertArrayHasKey('name', $user);
        self::assertArrayNotHasKey('email', $user);
    }

    public function test_first_array(): void
    {
        $user = self::$orm->table('users')->where('status', '=', 'active')->orderBy('id', 'asc')->firstArray();
        self::assertIsArray($user);
        self::assertSame('Alice', $user['name']);
    }

    public function test_find_one(): void
    {
        $user = self::$orm->table('users')->where('status', '=', 'active')->orderBy('id', 'asc')->findOne();
        self::assertInstanceOf(VersaModel::class, $user);
        self::assertSame('Alice', $user->name);
    }

    public function test_find(): void
    {
        $user = self::$orm->table('users')->find(1);
        self::assertInstanceOf(VersaModel::class, $user);
        self::assertSame('Alice', $user->name);
    }

    public function test_find_with_custom_pk(): void
    {
        $product = self::$orm->table('products')->find('P001', 'sku');
        self::assertInstanceOf(VersaModel::class, $product);
        self::assertSame('Laptop', $product->name);
    }

    public function test_count(): void
    {
        $count = self::$orm->table('users')->where('status', '=', 'active')->count();
        self::assertSame(2, $count);
    }

    public function test_exists(): void
    {
        $exists = self::$orm->table('users')->where('email', '=', 'bob@example.com')->exists();
        self::assertTrue($exists);

        $doesNotExist = self::$orm->table('users')->where('email', '=', 'nobody@example.com')->exists();
        self::assertFalse($doesNotExist);
    }

    /** @only */
    public function test_where(): void
    {
        $users = self::$orm->table('users')->where('status', '=', 'inactive')->findAll();
        self::assertCount(1, $users);
        self::assertSame('Bob', $users[0]->name);
    }

    public function test_where_greater_than(): void
    {
        $users = self::$orm->table('users')->where('id', '>', 1)->findAll();
        self::assertCount(2, $users);
    }

    public function test_or_where(): void
    {
        $users = self::$orm->table('users')->where('status', '=', 'inactive')->orWhere('id', '=', 3)->findAll();
        self::assertCount(2, $users);
    }

    public function test_where_in_debug(): void
    {
        // Create a separate ORM instance to avoid setup data being inserted
        global $config;
        $orm = new VersaORM([
            'driver' => $config['DB']['DB_DRIVER'],
            'host' => $config['DB']['DB_HOST'],
            'port' => $config['DB']['DB_PORT'],
            'database' => $config['DB']['DB_NAME'],
            'username' => $config['DB']['DB_USER'],
            'password' => $config['DB']['DB_PASS'],
            'debug' => true,
        ]);

        $query = $orm->table('users')->whereIn('id', [1, 3]);
        // The query will be dumped and exit in execute method
        $users = $query->findAll();
        self::assertCount(2, $users);
    }

    public function test_where_in(): void
    {
        $query = self::$orm->table('users')->whereIn('id', [1, 3]);
        // The query will be dumped and exit in execute method
        $users = $query->findAll();
        self::assertCount(2, $users);
    }

    public function test_where_not_in(): void
    {
        $users = self::$orm->table('users')->whereNotIn('id', [1, 3])->findAll();
        self::assertCount(1, $users);
        self::assertSame('Bob', $users[0]->name);
    }

    public function test_where_null(): void
    {
        self::$orm->table('posts')->insert(['user_id' => 1, 'title' => 'Draft Post', 'content' => '...', 'published_at' => null]);
        $posts = self::$orm->table('posts')->whereNull('published_at')->findAll();
        self::assertCount(4, $posts); // 3 from seed + 1 new
    }

    public function test_where_not_null(): void
    {
        self::$orm->table('posts')->where('id', '=', 1)->update(['published_at' => date('Y-m-d H:i:s')]);
        $posts = self::$orm->table('posts')->whereNotNull('published_at')->findAll();
        self::assertCount(1, $posts);
    }

    public function test_where_between(): void
    {
        $products = self::$orm->table('products')->whereBetween('price', 20, 30)->findAll();
        self::assertCount(1, $products);
        self::assertSame('Mouse', $products[0]->name);
    }

    public function test_where_not_between(): void
    {
        $products = self::$orm->table('products')->whereNotBetween('price', 20, 30)->findAll();
        // Solo debe devolver productos fuera del rango 20-30
        $names = array_map(fn ($p) => $p->name, $products);
        self::assertContains('Keyboard', $names);
        self::assertContains('Monitor', $names);
        self::assertNotContains('Mouse', $names);
    }

    public function test_where_raw(): void
    {
        $users = self::$orm->table('users')->whereRaw('LOWER(name) = ?', ['alice'])->findAll();
        self::assertCount(1, $users);
        self::assertSame('Alice', $users[0]->name);
    }

    // ======================================================================
    // JOIN Clauses
    // ======================================================================

    public function test_join(): void
    {
        $posts = self::$orm->table('posts')
            ->select(['posts.title', 'users.name as author'])
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->where('users.status', '=', 'active')
            ->getAll();

        self::assertCount(2, $posts);
        self::assertSame('Alice', $posts[0]['author']);
    }

    public function test_left_join(): void
    {
        self::$orm->table('users')->insert(['name' => 'Eve', 'email' => 'eve@example.com']);
        $users = self::$orm->table('users')
            ->select(['users.name', 'posts.id as post_id'])
            ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
            ->whereNull('posts.id')
            ->getAll();

        self::assertCount(2, $users); // Charlie and Eve have no posts
    }

    // ======================================================================
    // Order, Group, Limit, Offset
    // ======================================================================

    public function test_order_by(): void
    {
        $users = self::$orm->table('users')->orderBy('name', 'desc')->findAll();
        self::assertSame('Charlie', $users[0]->name);
        self::assertSame('Bob', $users[1]->name);
        self::assertSame('Alice', $users[2]->name);
    }

    public function test_limit(): void
    {
        $users = self::$orm->table('users')->limit(2)->orderBy('id', 'asc')->findAll();
        self::assertCount(2, $users);
        self::assertSame('Alice', $users[0]->name);
    }

    public function test_offset(): void
    {
        $users = self::$orm->table('users')->limit(1)->offset(1)->orderBy('id', 'asc')->findAll();
        self::assertCount(1, $users);
        self::assertSame('Bob', $users[0]->name);
    }

    public function test_group_by(): void
    {
        // Test simple groupBy
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as count'])
            ->groupBy('status')
            ->orderBy('status', 'asc')
            ->get();

        self::assertCount(2, $results);
        self::assertSame('active', $results[0]['status']);
        self::assertSame(2, $results[0]['count']);
        self::assertSame('inactive', $results[1]['status']);
        self::assertSame(1, $results[1]['count']);
    }

    public function test_group_by_multiple_columns(): void
    {
        // Test groupBy with multiple columns
        $results = self::$orm->table('posts')
            ->select(['user_id', 'COUNT(*) as post_count'])
            ->groupBy(['user_id'])
            ->orderBy('user_id', 'asc')
            ->get();

        self::assertCount(2, $results); // Alice has 2 posts, Bob has 1 post
        self::assertSame(1, $results[0]['user_id']);
        self::assertSame(2, $results[0]['post_count']);
        self::assertSame(2, $results[1]['user_id']);
        self::assertSame(1, $results[1]['post_count']);
    }

    public function test_having(): void
    {
        // Test groupBy with having
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as count'])
            ->groupBy('status')
            ->having('count', '>', 1)
            ->get();

        self::assertCount(1, $results);
        self::assertSame('active', $results[0]['status']);
        self::assertSame(2, $results[0]['count']);
    }

    public function test_having_multiple_conditions(): void
    {
        // Test having with multiple conditions
        $results = self::$orm->table('users')
            ->select(['status', 'COUNT(*) as count'])
            ->groupBy('status')
            ->having('count', '>=', 1)
            ->having('count', '<=', 2)
            ->orderBy('status', 'asc')
            ->get();

        self::assertCount(2, $results); // Both groups should match
        self::assertSame('active', $results[0]['status']);
        self::assertSame('inactive', $results[1]['status']);
    }

    // ======================================================================
    // Write Operations (INSERT, UPDATE, DELETE)
    // ======================================================================

    public function test_insert(): void
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

    public function test_insert_get_id(): void
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

    public function test_update(): void
    {
        $updated = self::$orm->table('users')
            ->where('email', '=', 'alice@example.com')
            ->update(['status' => 'on_vacation']);

        self::assertInstanceOf(QueryBuilder::class, $updated);

        $alice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        self::assertSame('on_vacation', $alice->status);
    }

    public function test_delete(): void
    {
        $deleted = self::$orm->table('users')
            ->where('email', '=', 'bob@example.com')
            ->delete();

        self::assertNull($deleted);
        $bob = self::$orm->table('users')->where('email', '=', 'bob@example.com')->findOne();
        self::assertNull($bob);
    }

    /**
     * Test adicional para verificar comportamiento de insertGetId en casos edge.
     */
    public function test_insert_get_id_return_types(): void
    {
        // Test 1: Verificar que devuelve int, no string
        $id1 = self::$orm->table('users')->insertGetId([
            'name' => 'TypeTest1',
            'email' => 'type1@example.com',
            'status' => 'active',
        ]);

        self::assertIsInt($id1, 'First insertGetId should return int');
        self::assertNotEmpty($id1, 'ID should not be empty');

        // Test 2: Múltiples inserciones deben devolver IDs incrementales
        $id2 = self::$orm->table('users')->insertGetId([
            'name' => 'TypeTest2',
            'email' => 'type2@example.com',
            'status' => 'active',
        ]);

        self::assertIsInt($id2, 'Second insertGetId should return int');
        self::assertGreaterThan($id1, $id2, 'Second ID should be greater than first');

        // Test 3: Verificar que el ID es utilizable directamente en operaciones
        $foundUser = self::$orm->table('users')->where('id', '=', $id1)->findOne();
        self::assertNotNull($foundUser, 'Should find user by returned ID');
        self::assertSame('TypeTest1', $foundUser->name);

        // Test 4: Verificar que no hay problemas de tipo en comparaciones
        self::assertTrue($id1 === (int) $id1, 'ID should be strict int type');
        self::assertTrue(is_int($id1), 'ID should pass is_int() check');
    }

    // ==================================================================
    // Derived UNION (fromUnion) Feature
    // ==================================================================

    public function test_from_union_derived_table(): void
    {
        $rows = self::$orm->table('posts')
            ->fromUnion([
                function (QueryBuilder $q): void {
                    $q->select(['id', 'user_id', 'title'])->where('id', '=', 1);
                },
                function (QueryBuilder $q): void {
                    $q->select(['id', 'user_id', 'title'])->where('id', '=', 2);
                },
            ], 'pu')
            ->select(['pu.id', 'pu.user_id', 'pu.title', 'users.name as author'])
            ->join('users', 'pu.user_id', '=', 'users.id')
            ->orderBy('pu.id', 'asc')
            ->getAll();

        self::assertCount(2, $rows, 'Debe devolver 2 filas (UNION sin duplicados)');
        self::assertSame(1, (int) $rows[0]['id']);
        self::assertSame(2, (int) $rows[1]['id']);
        self::assertSame('Alice', $rows[0]['author']);
    }

    public function test_from_union_all_duplicates(): void
    {
        $rows = self::$orm->table('posts')
            ->fromUnion([
                function (QueryBuilder $q): void {
                    $q->select(['id', 'user_id', 'title'])->where('id', '=', 1);
                },
                function (QueryBuilder $q): void {
                    $q->select(['id', 'user_id', 'title'])->where('id', '=', 1);
                },
            ], 'pu', true) // UNION ALL
            ->select(['pu.id', 'pu.user_id', 'pu.title'])
            ->orderBy('pu.id', 'asc')
            ->getAll();

        self::assertCount(2, $rows, 'UNION ALL debe conservar duplicados');
        self::assertSame((int) $rows[0]['id'], (int) $rows[1]['id'], 'Ambas filas deben ser el mismo id por duplicado');
    }

    public function test_from_union_invalid_empty(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->table('posts')->fromUnion([], 'x');
    }
}
