<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

use PHPUnit\Framework\TestCase as BaseTestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

require_once __DIR__ . '/bootstrap.php';
/**
 * @group mysql
 */
class TestCase extends BaseTestCase
{
    public static ?VersaORM $orm = null;

    private static bool $schemaCreated = false;

    public static function setUpBeforeClass(): void
    {
        if (self::$orm === null) {
            global $config;
            $dbConfig = [
                'engine' => $config['DB']['engine'],
                'driver' => $config['DB']['DB_DRIVER'],
                'database' => $config['DB']['DB_NAME'],
                'debug' => $config['DB']['debug'],
                'host' => $config['DB']['DB_HOST'] ?? '',
                'port' => (int) ($config['DB']['DB_PORT'] ?? 0),
                'username' => $config['DB']['DB_USER'] ?? '',
                'password' => $config['DB']['DB_PASS'] ?? '',
            ];

            self::$orm = new VersaORM($dbConfig);
            VersaModel::setORM(self::$orm);
        }
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$schemaCreated) {
            // self::dropSchema(); // Drop schema can be slow, rollback is enough
            self::$schemaCreated = false;
        }
        self::$orm = null;
    }

    protected function setUp(): void
    {
        // Reinicia el esquema y los datos antes de cada test para asegurar el aislamiento.
        self::createSchema();
        self::seedData();
    }

    protected function tearDown(): void
    {
        // No es necesario hacer rollback si el esquema se recrea cada vez.
        global $config;

        if (($config['DB']['DB_DRIVER'] ?? '') === 'mysql') {
            self::$orm->exec('SET FOREIGN_KEY_CHECKS = 0;');
        }
        self::$orm->exec('DROP TABLE IF EXISTS role_user;');
        self::$orm->exec('DROP TABLE IF EXISTS posts;');
        self::$orm->exec('DROP TABLE IF EXISTS profiles;');
        self::$orm->exec('DROP TABLE IF EXISTS roles;');
        self::$orm->exec('DROP TABLE IF EXISTS users;');
        self::$orm->exec('DROP TABLE IF EXISTS products;');
        self::$orm->exec('DROP TABLE IF EXISTS test_users;');

        if (($config['DB']['DB_DRIVER'] ?? '') === 'mysql') {
            self::$orm->exec('SET FOREIGN_KEY_CHECKS = 1;');
        }
    }

    protected static function createSchema(): void
    {
        self::dropSchema(); // Ensure clean state before creating

        // Configuración específica para MySQL
        global $config;

        if ($config['DB']['DB_DRIVER'] === 'mysql') {
            // Desactivar checks durante la creación para evitar problemas de orden
            self::$orm->exec('SET FOREIGN_KEY_CHECKS = 0;');
            self::$orm->exec(
                'SET sql_mode = "STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO";',
            );
        }

        self::$orm->schemaCreate(
            'users',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'email', 'type' => 'VARCHAR(191)', 'nullable' => false, 'default' => ''],
                ['name' => 'status', 'type' => 'VARCHAR(50)'],
                ['name' => 'created_at', 'type' => 'TIMESTAMP', 'default' => 'CURRENT_TIMESTAMP'],
            ],
            [
                'engine' => 'InnoDB',
                'constraints' => [
                    'unique' => [['name' => 'users_email_unique', 'columns' => ['email']]],
                ],
            ],
        );

        self::$orm->schemaCreate(
            'profiles',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'user_id', 'type' => 'INT'],
                ['name' => 'bio', 'type' => 'TEXT'],
            ],
            [
                'engine' => 'InnoDB',
                'constraints' => [
                    'foreign' => [[
                        'name' => 'fk_profiles_users',
                        'columns' => ['user_id'],
                        'refTable' => 'users',
                        'refColumns' => ['id'],
                        'onDelete' => 'cascade',
                    ]],
                ],
            ],
        );

        self::$orm->schemaCreate(
            'posts',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'user_id', 'type' => 'INT'],
                ['name' => 'title', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'content', 'type' => 'TEXT'],
                ['name' => 'published_at', 'type' => 'DATETIME'],
                ['name' => 'published', 'type' => 'BOOLEAN', 'default' => false],
            ],
            [
                'engine' => 'InnoDB',
                'constraints' => [
                    'foreign' => [[
                        'name' => 'fk_posts_users',
                        'columns' => ['user_id'],
                        'refTable' => 'users',
                        'refColumns' => ['id'],
                        'onDelete' => 'cascade',
                    ]],
                ],
            ],
        );

        self::$orm->schemaCreate(
            'roles',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
            ],
            ['engine' => 'InnoDB'],
        );

        self::$orm->schemaCreate(
            'role_user',
            [
                ['name' => 'user_id', 'type' => 'INT', 'nullable' => false],
                ['name' => 'role_id', 'type' => 'INT', 'nullable' => false],
            ],
            [
                'engine' => 'InnoDB',
                'primary_key' => ['user_id', 'role_id'],
                'constraints' => [
                    'foreign' => [
                        [
                            'name' => 'fk_ru_user',
                            'columns' => ['user_id'],
                            'refTable' => 'users',
                            'refColumns' => ['id'],
                            'onDelete' => 'cascade',
                        ],
                        [
                            'name' => 'fk_ru_role',
                            'columns' => ['role_id'],
                            'refTable' => 'roles',
                            'refColumns' => ['id'],
                            'onDelete' => 'cascade',
                        ],
                    ],
                ],
            ],
        );

        self::$orm->schemaCreate(
            'products',
            [
                ['name' => 'sku', 'type' => 'VARCHAR(50)', 'primary' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'price', 'type' => 'DECIMAL(10, 2)'],
                ['name' => 'stock', 'type' => 'INT', 'default' => 0],
                ['name' => 'description', 'type' => 'TEXT'],
                ['name' => 'category', 'type' => 'VARCHAR(100)'],
            ],
            ['engine' => 'InnoDB'],
        );

        if ($config['DB']['DB_DRIVER'] === 'mysql') {
            // Reactivar checks una vez creado todo
            self::$orm->exec('SET FOREIGN_KEY_CHECKS = 1;');
        }
    }

    protected static function dropSchema(): void
    {
        global $config;

        if (($config['DB']['DB_DRIVER'] ?? '') === 'mysql') {
            self::$orm->exec('SET FOREIGN_KEY_CHECKS = 0;');
        }
        // Dropear en orden seguro para FKs
        self::$orm->schemaDrop('role_user');
        self::$orm->schemaDrop('posts');
        self::$orm->schemaDrop('profiles');
        self::$orm->schemaDrop('roles');
        self::$orm->schemaDrop('users');
        self::$orm->schemaDrop('products');
        self::$orm->schemaDrop('test_users');

        if (($config['DB']['DB_DRIVER'] ?? '') === 'mysql') {
            self::$orm->exec('SET FOREIGN_KEY_CHECKS = 1;');
        }
    }

    protected static function seedData(): void
    {
        // Seed users (omitir ID, dejar que SQLite asigne automáticamente)
        self::$orm->table('users')->insert(['name' => 'Alice', 'email' => 'alice@example.com', 'status' => 'active']);
        self::$orm->table('users')->insert(['name' => 'Bob', 'email' => 'bob@example.com', 'status' => 'inactive']);
        self::$orm
            ->table('users')
            ->insert(['name' => 'Charlie', 'email' => 'charlie@example.com', 'status' => 'active']);

        // Seed posts (usar IDs 1, 2, 3 como user_id)
        self::$orm
            ->table('posts')
            ->insert(['user_id' => 1, 'title' => 'Alice Post 1', 'content' => 'Content 1', 'published' => true]);
        self::$orm->table('posts')->insert(['user_id' => 1, 'title' => 'Alice Post 2', 'content' => 'Content 2']);
        self::$orm->table('posts')->insert(['user_id' => 2, 'title' => 'Bob Post 1', 'content' => 'Content 3']);

        // Seed products
        self::$orm->table('products')->insert(['sku' => 'P001', 'name' => 'Laptop', 'price' => 1200.50, 'stock' => 10]);
        self::$orm->table('products')->insert(['sku' => 'P002', 'name' => 'Mouse', 'price' => 25.00, 'stock' => 100]);
        self::$orm->table('products')->insert(['sku' => 'P003', 'name' => 'Keyboard', 'price' => 15.00, 'stock' => 50]);
        self::$orm->table('products')->insert(['sku' => 'P004', 'name' => 'Monitor', 'price' => 300.00, 'stock' => 20]);

        // Seed relationships data
        self::$orm->table('profiles')->insert(['user_id' => 1, 'bio' => 'Alice bio']);
        self::$orm->table('roles')->insert(['name' => 'Admin']);
        self::$orm->table('roles')->insert(['name' => 'Editor']);
        self::$orm->table('roles')->insert(['name' => 'Viewer']);
        self::$orm->table('roles')->insert(['name' => 'externo']);

        self::$orm->table('role_user')->insert(['user_id' => 1, 'role_id' => 1]);
        self::$orm->table('role_user')->insert(['user_id' => 1, 'role_id' => 2]);
        self::$orm->table('role_user')->insert(['user_id' => 2, 'role_id' => 2]);
    }
}
