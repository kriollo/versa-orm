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
        static::assertCount(3, $users);
        static::assertIsArray($users[0]);
        static::assertArrayHasKey('email', $users[0]);
    }

    public function test_find_all(): void
    {
        $users = self::$orm->table('users')->findAll();
        static::assertCount(3, $users);
        static::assertInstanceOf(VersaModel::class, $users[0]);
        static::assertSame('alice@example.com', $users[0]->email);
    }

    public function test_select_specific_columns(): void
    {
        $user = self::$orm
            ->table('users')
            ->select(['id', 'name'])
            ->where('email', '=', 'alice@example.com')
            ->firstArray();
        static::assertCount(2, $user);
        static::assertArrayHasKey('id', $user);
        static::assertArrayHasKey('name', $user);
        static::assertArrayNotHasKey('email', $user);
    }

    public function test_first_array(): void
    {
        $user = self::$orm->table('users')->where('status', '=', 'active')->orderBy('id', 'asc')->firstArray();
        static::assertIsArray($user);
        static::assertSame('Alice', $user['name']);
    }

    public function test_find_one(): void
    {
        $user = self::$orm->table('users')->where('status', '=', 'active')->orderBy('id', 'asc')->findOne();
        static::assertInstanceOf(VersaModel::class, $user);
        static::assertSame('Alice', $user->name);
    }

    public function test_find(): void
    {
        $user = self::$orm->table('users')->find(1);
        static::assertInstanceOf(VersaModel::class, $user);
        static::assertSame('Alice', $user->name);
    }

    public function test_find_with_custom_pk(): void
    {
        $product = self::$orm->table('products')->find('P001', 'sku');
        static::assertInstanceOf(VersaModel::class, $product);
        static::assertSame('Laptop', $product->name);
    }

    public function test_count(): void
    {
        $count = self::$orm->table('users')->where('status', '=', 'active')->count();
        static::assertSame(2, $count);
    }

    public function test_exists(): void
    {
        $exists = self::$orm->table('users')->where('email', '=', 'bob@example.com')->exists();
        static::assertTrue($exists);

        $doesNotExist = self::$orm->table('users')->where('email', '=', 'nobody@example.com')->exists();
        static::assertFalse($doesNotExist);
    }

    /** @only */
    public function test_where(): void
    {
        $users = self::$orm->table('users')->where('status', '=', 'inactive')->findAll();
        static::assertCount(1, $users);
        static::assertSame('Bob', $users[0]->name);
    }

    public function test_where_greater_than(): void
    {
        $users = self::$orm->table('users')->where('id', '>', 1)->findAll();
        static::assertCount(2, $users);
    }

    public function test_or_where(): void
    {
        $users = self::$orm->table('users')->where('status', '=', 'inactive')->orWhere('id', '=', 3)->findAll();
        static::assertCount(2, $users);
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
        static::assertCount(2, $users);
    }

    public function test_where_in(): void
    {
        $query = self::$orm->table('users')->whereIn('id', [1, 3]);
        // The query will be dumped and exit in execute method
        $users = $query->findAll();
        static::assertCount(2, $users);
    }

    public function test_where_not_in(): void
    {
        $users = self::$orm->table('users')->whereNotIn('id', [1, 3])->findAll();
        static::assertCount(1, $users);
        static::assertSame('Bob', $users[0]->name);
    }

    public function test_where_null(): void
    {
        self::$orm
            ->table('posts')
            ->insert(['user_id' => 1, 'title' => 'Draft Post', 'content' => '...', 'published_at' => null]);
        $posts = self::$orm->table('posts')->whereNull('published_at')->findAll();
        static::assertCount(4, $posts); // 3 from seed + 1 new
    }

    public function test_where_not_null(): void
    {
        self::$orm->table('posts')->where('id', '=', 1)->update(['published_at' => date('Y-m-d H:i:s')]);
        $posts = self::$orm->table('posts')->whereNotNull('published_at')->findAll();
        static::assertCount(1, $posts);
    }

    public function test_where_between(): void
    {
        $products = self::$orm->table('products')->whereBetween('price', 20, 30)->findAll();
        static::assertCount(1, $products);
        static::assertSame('Mouse', $products[0]->name);
    }

    public function test_where_not_between(): void
    {
        $products = self::$orm->table('products')->whereNotBetween('price', 20, 30)->findAll();
        // Solo debe devolver productos fuera del rango 20-30
        $names = array_map(static fn($p) => $p->name, $products);
        static::assertContains('Keyboard', $names);
        static::assertContains('Monitor', $names);
        static::assertNotContains('Mouse', $names);
    }

    public function test_where_raw(): void
    {
        $users = self::$orm->table('users')->whereRaw('LOWER(name) = ?', ['alice'])->findAll();
        static::assertCount(1, $users);
        static::assertSame('Alice', $users[0]->name);
    }

    // ======================================================================
    // JOIN Clauses
    // ======================================================================

    public function test_join(): void
    {
        $posts = self::$orm
            ->table('posts')
            ->select(['posts.title', 'users.name as author'])
            ->join('users', 'posts.user_id', '=', 'users.id')
            ->where('users.status', '=', 'active')
            ->getAll();

        static::assertCount(2, $posts);
        static::assertSame('Alice', $posts[0]['author']);
    }

    public function test_left_join(): void
    {
        self::$orm->table('users')->insert(['name' => 'Eve', 'email' => 'eve@example.com']);
        $users = self::$orm
            ->table('users')
            ->select(['users.name', 'posts.id as post_id'])
            ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
            ->whereNull('posts.id')
            ->getAll();

        static::assertCount(2, $users); // Charlie and Eve have no posts
    }

    // ======================================================================
    // Order, Group, Limit, Offset
    // ======================================================================

    public function test_order_by(): void
    {
        $users = self::$orm->table('users')->orderBy('name', 'desc')->findAll();
        static::assertSame('Charlie', $users[0]->name);
        static::assertSame('Bob', $users[1]->name);
        static::assertSame('Alice', $users[2]->name);
    }

    public function test_limit(): void
    {
        $users = self::$orm->table('users')->limit(2)->orderBy('id', 'asc')->findAll();
        static::assertCount(2, $users);
        static::assertSame('Alice', $users[0]->name);
    }

    public function test_offset(): void
    {
        $users = self::$orm->table('users')->limit(1)->offset(1)->orderBy('id', 'asc')->findAll();
        static::assertCount(1, $users);
        static::assertSame('Bob', $users[0]->name);
    }

    public function test_group_by(): void
    {
        // Test simple groupBy
        $results = self::$orm
            ->table('users')
            ->select(['status', 'COUNT(*) as count'])
            ->groupBy('status')
            ->orderBy('status', 'asc')
            ->get();

        static::assertCount(2, $results);
        static::assertSame('active', $results[0]['status']);
        static::assertSame(2, $results[0]['count']);
        static::assertSame('inactive', $results[1]['status']);
        static::assertSame(1, $results[1]['count']);
    }

    public function test_group_by_multiple_columns(): void
    {
        // Test groupBy with multiple columns
        $results = self::$orm
            ->table('posts')
            ->select(['user_id', 'COUNT(*) as post_count'])
            ->groupBy(['user_id'])
            ->orderBy('user_id', 'asc')
            ->get();

        static::assertCount(2, $results); // Alice has 2 posts, Bob has 1 post
        static::assertSame(1, $results[0]['user_id']);
        static::assertSame(2, $results[0]['post_count']);
        static::assertSame(2, $results[1]['user_id']);
        static::assertSame(1, $results[1]['post_count']);
    }

    public function test_having(): void
    {
        // Test groupBy with having
        $results = self::$orm
            ->table('users')
            ->select(['status', 'COUNT(*) as count'])
            ->groupBy('status')
            ->having('count', '>', 1)
            ->get();

        static::assertCount(1, $results);
        static::assertSame('active', $results[0]['status']);
        static::assertSame(2, $results[0]['count']);
    }

    public function test_having_multiple_conditions(): void
    {
        // Test having with multiple conditions
        $results = self::$orm
            ->table('users')
            ->select(['status', 'COUNT(*) as count'])
            ->groupBy('status')
            ->having('count', '>=', 1)
            ->having('count', '<=', 2)
            ->orderBy('status', 'asc')
            ->get();

        static::assertCount(2, $results); // Both groups should match
        static::assertSame('active', $results[0]['status']);
        static::assertSame('inactive', $results[1]['status']);
    }

    // ======================================================================
    // Write Operations (INSERT, UPDATE, DELETE)
    // ======================================================================

    public function test_insert(): void
    {
        self::$orm
            ->table('users')
            ->insert([
                'name' => 'Frank',
                'email' => 'frank@example.com',
                'status' => 'active',
            ]);

        $frank = self::$orm->table('users')->where('email', '=', 'frank@example.com')->findOne();
        static::assertNotNull($frank);
        static::assertSame('Frank', $frank->name);
    }

    public function test_insert_get_id(): void
    {
        $id = self::$orm
            ->table('users')
            ->insertGetId([
                'name' => 'Grace',
                'email' => 'grace@example.com',
                'status' => 'active',
            ]);

        // Verificar que el ID devuelto es un entero, no un string
        static::assertIsInt($id, 'insertGetId() should return an integer');
        static::assertGreaterThan(0, $id, 'insertGetId() should return a positive integer');

        // Verificar que el registro se insertó correctamente
        $grace = self::$orm->table('users')->find($id);
        static::assertNotNull($grace, 'Should be able to find the inserted record');
        static::assertSame('Grace', $grace->name);
    }

    public function test_update(): void
    {
        $updated = self::$orm
            ->table('users')
            ->where('email', '=', 'alice@example.com')
            ->update(['status' => 'on_vacation']);

        static::assertInstanceOf(QueryBuilder::class, $updated);

        $alice = self::$orm->table('users')->where('email', '=', 'alice@example.com')->findOne();
        static::assertSame('on_vacation', $alice->status);
    }

    public function test_delete(): void
    {
        $deleted = self::$orm->table('users')->where('email', '=', 'bob@example.com')->delete();

        static::assertNull($deleted);
        $bob = self::$orm->table('users')->where('email', '=', 'bob@example.com')->findOne();
        static::assertNull($bob);
    }

    /**
     * Test adicional para verificar comportamiento de insertGetId en casos edge.
     */
    public function test_insert_get_id_return_types(): void
    {
        // Test 1: Verificar que devuelve int, no string
        $id1 = self::$orm
            ->table('users')
            ->insertGetId([
                'name' => 'TypeTest1',
                'email' => 'type1@example.com',
                'status' => 'active',
            ]);

        static::assertIsInt($id1, 'First insertGetId should return int');
        static::assertNotEmpty($id1, 'ID should not be empty');

        // Test 2: Múltiples inserciones deben devolver IDs incrementales
        $id2 = self::$orm
            ->table('users')
            ->insertGetId([
                'name' => 'TypeTest2',
                'email' => 'type2@example.com',
                'status' => 'active',
            ]);

        static::assertIsInt($id2, 'Second insertGetId should return int');
        static::assertGreaterThan($id1, $id2, 'Second ID should be greater than first');

        // Test 3: Verificar que el ID es utilizable directamente en operaciones
        $foundUser = self::$orm->table('users')->where('id', '=', $id1)->findOne();
        static::assertNotNull($foundUser, 'Should find user by returned ID');
        static::assertSame('TypeTest1', $foundUser->name);

        // Test 4: Verificar que no hay problemas de tipo en comparaciones
        static::assertTrue($id1 === (int) $id1, 'ID should be strict int type');
        static::assertTrue(is_int($id1), 'ID should pass is_int() check');
    }

    // ==================================================================
    // Derived UNION (fromUnion) Feature
    // ==================================================================

    public function test_from_union_derived_table(): void
    {
        $rows = self::$orm
            ->table('posts')
            ->fromUnion([
                static function (QueryBuilder $q): void {
                    $q->select(['id', 'user_id', 'title'])->where('id', '=', 1);
                },
                static function (QueryBuilder $q): void {
                    $q->select(['id', 'user_id', 'title'])->where('id', '=', 2);
                },
            ], 'pu')
            ->select(['pu.id', 'pu.user_id', 'pu.title', 'users.name as author'])
            ->join('users', 'pu.user_id', '=', 'users.id')
            ->orderBy('pu.id', 'asc')
            ->getAll();

        static::assertCount(2, $rows, 'Debe devolver 2 filas (UNION sin duplicados)');
        static::assertSame(1, (int) $rows[0]['id']);
        static::assertSame(2, (int) $rows[1]['id']);
        static::assertSame('Alice', $rows[0]['author']);
    }

    public function test_from_union_all_duplicates(): void
    {
        $rows = self::$orm
            ->table('posts')
            ->fromUnion(
                [
                    static function (QueryBuilder $q): void {
                        $q->select(['id', 'user_id', 'title'])->where('id', '=', 1);
                    },
                    static function (QueryBuilder $q): void {
                        $q->select(['id', 'user_id', 'title'])->where('id', '=', 1);
                    },
                ],
                'pu',
                true,
            ) // UNION ALL
            ->select(['pu.id', 'pu.user_id', 'pu.title'])
            ->orderBy('pu.id', 'asc')
            ->getAll();

        static::assertCount(2, $rows, 'UNION ALL debe conservar duplicados');
        static::assertSame(
            (int) $rows[0]['id'],
            (int) $rows[1]['id'],
            'Ambas filas deben ser el mismo id por duplicado',
        );
    }

    public function test_from_union_invalid_empty(): void
    {
        $this->expectException(VersaORMException::class);
        self::$orm->table('posts')->fromUnion([], 'x');
    }
}
