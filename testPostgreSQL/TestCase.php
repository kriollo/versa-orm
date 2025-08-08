<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use PHPUnit\Framework\TestCase as BaseTestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

require_once __DIR__ . '/bootstrap.php';

class TestCase extends BaseTestCase
{
    public static ?VersaORM $orm       = null;
    private static bool $schemaCreated = false;

    public static function setUpBeforeClass(): void
    {
        if (self::$orm === null) {
            global $config;
            $dbConfig = [
                'engine'   => $config['DB']['engine'],
                'driver'   => $config['DB']['DB_DRIVER'],
                'database' => $config['DB']['DB_NAME'],
                'debug'    => $config['DB']['debug'],
                'host'     => $config['DB']['DB_HOST'] ?? '',
                'port'     => (int)($config['DB']['DB_PORT'] ?? 0),
                'username' => $config['DB']['DB_USER'] ?? '',
                'password' => $config['DB']['DB_PASS'] ?? '',
            ];

            self::$orm = new VersaORM($dbConfig);
            VersaModel::setORM(self::$orm);
        }
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

    public static function tearDownAfterClass(): void
    {
        if (self::$schemaCreated) {
            // self::dropSchema(); // Drop schema can be slow, rollback is enough
            self::$schemaCreated = false;
        }
        self::$orm = null;
    }

    protected static function createSchema(): void
    {
        self::dropSchema(); // Ensure clean state before creating

        // Configuración específica por driver
        global $config;
        $driver = $config['DB']['DB_DRIVER'] ?? '';

        if ($driver === 'mysql') {
            // Desactivar checks durante la creación para evitar problemas de orden
            self::$orm->exec('SET FOREIGN_KEY_CHECKS = 0;');
            self::$orm->exec('SET sql_mode = "STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO";');
            // users
            self::$orm->schemaCreate('users', [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'email', 'type' => 'VARCHAR(191)', 'nullable' => false],
                ['name' => 'status', 'type' => 'VARCHAR(50)'],
                ['name' => 'created_at', 'type' => 'TIMESTAMP'],
            ], ['engine' => 'InnoDB']);
            // unique email
            self::$orm->exec('ALTER TABLE `users` ADD UNIQUE (`email`)');

            // profiles
            self::$orm->schemaCreate('profiles', [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'user_id', 'type' => 'INT'],
                ['name' => 'bio', 'type' => 'TEXT'],
            ], ['engine' => 'InnoDB']);
            self::$orm->exec('ALTER TABLE `profiles` ADD CONSTRAINT `fk_profiles_users` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE');

            // posts
            self::$orm->schemaCreate('posts', [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'user_id', 'type' => 'INT'],
                ['name' => 'title', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'content', 'type' => 'TEXT'],
                ['name' => 'published_at', 'type' => 'DATETIME'],
            ], ['engine' => 'InnoDB']);
            self::$orm->exec('ALTER TABLE `posts` ADD CONSTRAINT `fk_posts_users` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE');

            // roles
            self::$orm->schemaCreate('roles', [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
            ], ['engine' => 'InnoDB']);

            // role_user (pivot)
            self::$orm->schemaCreate('role_user', [
                ['name' => 'user_id', 'type' => 'INT', 'nullable' => false],
                ['name' => 'role_id', 'type' => 'INT', 'nullable' => false],
            ], ['engine' => 'InnoDB', 'primary_key' => ['user_id', 'role_id']]);
            self::$orm->exec('ALTER TABLE `role_user` ADD CONSTRAINT `fk_ru_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE');
            self::$orm->exec('ALTER TABLE `role_user` ADD CONSTRAINT `fk_ru_role` FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE CASCADE');

            // products
            self::$orm->schemaCreate('products', [
                ['name' => 'sku', 'type' => 'VARCHAR(50)', 'nullable' => false, 'primary' => true],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'price', 'type' => 'DECIMAL(10, 2)'],
                ['name' => 'stock', 'type' => 'INT'],
                ['name' => 'description', 'type' => 'TEXT'],
                ['name' => 'category', 'type' => 'VARCHAR(100)'],
            ], ['engine' => 'InnoDB']);

            // Reactivar checks una vez creado todo
            self::$orm->exec('SET FOREIGN_KEY_CHECKS = 1;');
        } elseif ($driver === 'postgresql' || $driver === 'pgsql') {
            // PostgreSQL DDL (sin ENGINE, con identity columns y tipos compatibles)
            self::$orm->schemaCreate('users', [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'email', 'type' => 'VARCHAR(191)', 'nullable' => false],
                ['name' => 'status', 'type' => 'VARCHAR(50)'],
                ['name' => 'created_at', 'type' => 'TIMESTAMP'],
            ], [
                'constraints' => [
                    'unique' => [['name' => 'users_email_unique', 'columns' => ['email']]],
                ],
            ]);

            self::$orm->schemaCreate('profiles', [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'user_id', 'type' => 'INT'],
                ['name' => 'bio', 'type' => 'TEXT'],
            ], [
                'constraints' => [
                    'foreign' => [[
                        'name'       => 'fk_profiles_users',
                        'columns'    => ['user_id'],
                        'refTable'   => 'users',
                        'refColumns' => ['id'],
                        'onDelete'   => 'cascade',
                    ]],
                ],
            ]);

            self::$orm->schemaCreate('posts', [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'user_id', 'type' => 'INT'],
                ['name' => 'title', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'content', 'type' => 'TEXT'],
                ['name' => 'published_at', 'type' => 'TIMESTAMP'],
            ], [
                'constraints' => [
                    'foreign' => [[
                        'name'       => 'fk_posts_users',
                        'columns'    => ['user_id'],
                        'refTable'   => 'users',
                        'refColumns' => ['id'],
                        'onDelete'   => 'cascade',
                    ]],
                ],
            ]);

            self::$orm->schemaCreate('roles', [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
            ]);

            self::$orm->schemaCreate('role_user', [
                ['name' => 'user_id', 'type' => 'INT', 'nullable' => false],
                ['name' => 'role_id', 'type' => 'INT', 'nullable' => false],
            ], [
                'primary_key' => ['user_id', 'role_id'],
                'constraints' => [
                    'foreign' => [
                        [
                            'name'       => 'fk_role_user_user',
                            'columns'    => ['user_id'],
                            'refTable'   => 'users',
                            'refColumns' => ['id'],
                            'onDelete'   => 'cascade',
                        ],
                        [
                            'name'       => 'fk_role_user_role',
                            'columns'    => ['role_id'],
                            'refTable'   => 'roles',
                            'refColumns' => ['id'],
                            'onDelete'   => 'cascade',
                        ],
                    ],
                ],
            ]);

            self::$orm->schemaCreate('products', [
                ['name' => 'sku', 'type' => 'VARCHAR(50)', 'nullable' => false, 'primary' => true],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'price', 'type' => 'DECIMAL(10, 2)'],
                ['name' => 'stock', 'type' => 'INT'],
                ['name' => 'description', 'type' => 'TEXT'],
                ['name' => 'category', 'type' => 'VARCHAR(100)'],
            ]);
        } else {
            // Driver genérico (SQLite u otros) - sintaxis portable con constraints
            if ($driver === 'sqlite') {
                // Asegurar enforcement de FKs en SQLite
                self::$orm->exec('PRAGMA foreign_keys = ON;');
            }

            self::$orm->schemaCreate('users', [
                ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'email', 'type' => 'VARCHAR(191)', 'nullable' => false],
                ['name' => 'status', 'type' => 'VARCHAR(50)'],
                ['name' => 'created_at', 'type' => 'TEXT'],
            ], [
                'constraints' => [
                    'unique' => [['name' => 'users_email_unique', 'columns' => ['email']]],
                ],
            ]);

            self::$orm->schemaCreate('profiles', [
                ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'user_id', 'type' => 'INT'],
                ['name' => 'bio', 'type' => 'TEXT'],
            ], [
                'constraints' => [
                    'foreign' => [[
                        'name'       => 'fk_profiles_users',
                        'columns'    => ['user_id'],
                        'refTable'   => 'users',
                        'refColumns' => ['id'],
                        'onDelete'   => 'cascade',
                    ]],
                ],
            ]);

            self::$orm->schemaCreate('posts', [
                ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'user_id', 'type' => 'INT'],
                ['name' => 'title', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'content', 'type' => 'TEXT'],
                ['name' => 'published_at', 'type' => 'TEXT'],
            ], [
                'constraints' => [
                    'foreign' => [[
                        'name'       => 'fk_posts_users',
                        'columns'    => ['user_id'],
                        'refTable'   => 'users',
                        'refColumns' => ['id'],
                        'onDelete'   => 'cascade',
                    ]],
                ],
            ]);

            self::$orm->schemaCreate('roles', [
                ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
            ]);

            self::$orm->schemaCreate('role_user', [
                ['name' => 'user_id', 'type' => 'INT', 'nullable' => false],
                ['name' => 'role_id', 'type' => 'INT', 'nullable' => false],
            ], [
                'primary_key' => ['user_id', 'role_id'],
                'constraints' => [
                    'foreign' => [
                        [
                            'name'       => 'fk_role_user_user',
                            'columns'    => ['user_id'],
                            'refTable'   => 'users',
                            'refColumns' => ['id'],
                            'onDelete'   => 'cascade',
                        ],
                        [
                            'name'       => 'fk_role_user_role',
                            'columns'    => ['role_id'],
                            'refTable'   => 'roles',
                            'refColumns' => ['id'],
                            'onDelete'   => 'cascade',
                        ],
                    ],
                ],
            ]);

            self::$orm->schemaCreate('products', [
                ['name' => 'sku', 'type' => 'VARCHAR(50)', 'nullable' => false, 'primary' => true],
                ['name' => 'name', 'type' => 'VARCHAR(255)', 'nullable' => false],
                ['name' => 'price', 'type' => 'DECIMAL(10, 2)'],
                ['name' => 'stock', 'type' => 'INT'],
                ['name' => 'description', 'type' => 'TEXT'],
                ['name' => 'category', 'type' => 'VARCHAR(100)'],
            ]);
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
        self::$orm->table('users')->insert(['name' => 'Charlie', 'email' => 'charlie@example.com', 'status' => 'active']);

        // Seed posts (usar IDs 1, 2, 3 como user_id)
        self::$orm->table('posts')->insert(['user_id' => 1, 'title' => 'Alice Post 1', 'content' => 'Content 1']);
        self::$orm->table('posts')->insert(['user_id' => 1, 'title' => 'Alice Post 2', 'content' => 'Content 2']);
        self::$orm->table('posts')->insert(['user_id' => 2, 'title' => 'Bob Post 1', 'content' => 'Content 3']);

        // Seed products
        self::$orm->table('products')->insert(['sku' => 'P001', 'name' => 'Laptop', 'price' => 1200.50, 'stock' => 10]);
        self::$orm->table('products')->insert(['sku' => 'P002', 'name' => 'Mouse', 'price' => 25.00, 'stock' => 100]);

        // Seed relationships data
        self::$orm->table('profiles')->insert(['user_id' => 1, 'bio' => 'Alice bio']);
        self::$orm->table('roles')->insert(['name' => 'Admin']);
        self::$orm->table('roles')->insert(['name' => 'Editor']);
        self::$orm->table('role_user')->insert(['user_id' => 1, 'role_id' => 1]);
        self::$orm->table('role_user')->insert(['user_id' => 1, 'role_id' => 2]);
        self::$orm->table('role_user')->insert(['user_id' => 2, 'role_id' => 2]);
    }
}
