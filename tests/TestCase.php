<?php

// tests/TestCase.php

declare(strict_types=1);

namespace VersaORM\Tests;

use PHPUnit\Framework\TestCase as BaseTestCase;
use VersaORM\VersaORM;
use VersaORM\VersaModel;

class TestCase extends BaseTestCase
{
    protected static ?VersaORM $orm = null;

    public static function setUpBeforeClass(): void
    {
        if (self::$orm === null) {
            global $config;
            $dbConfig = [
                'driver' => $config['DB']['DB_DRIVER'],
                'host' => $config['DB']['DB_HOST'],
                'port' => $config['DB']['DB_PORT'],
                'database' => $config['DB']['DB_NAME'],
                'username' => $config['DB']['DB_USER'],
                'password' => $config['DB']['DB_PASS'],
                'debug' => $config['DB']['debug'],
            ];
            self::$orm = new VersaORM($dbConfig);
            VersaModel::setORM(self::$orm);
        }

        self::createSchema();
    }

    protected function setUp(): void
    {
        self::seedData();
    }

    protected function tearDown(): void
    {
        self::$orm->exec('SET FOREIGN_KEY_CHECKS = 0;');
        self::$orm->exec('TRUNCATE TABLE posts;');
        self::$orm->exec('TRUNCATE TABLE users;');
        self::$orm->exec('TRUNCATE TABLE products;');
        self::$orm->exec('SET FOREIGN_KEY_CHECKS = 1;');
    }

    public static function tearDownAfterClass(): void
    {
        self::dropSchema();
    }

    protected static function createSchema(): void
    {
        self::$orm->exec('DROP TABLE IF EXISTS posts;');
        self::$orm->exec('DROP TABLE IF EXISTS users;');
        self::$orm->exec('DROP TABLE IF EXISTS products;');

        self::$orm->exec('
            CREATE TABLE users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(191) UNIQUE NOT NULL,
                status VARCHAR(50) DEFAULT \'active\',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ');

        self::$orm->exec('
            CREATE TABLE posts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                title VARCHAR(255) NOT NULL,
                content TEXT,
                published_at TIMESTAMP NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        ');

        self::$orm->exec('
            CREATE TABLE products (
                sku VARCHAR(50) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                stock INT DEFAULT 0
            );
        ');
    }

    protected static function dropSchema(): void
    {
        self::$orm->exec('DROP TABLE IF EXISTS posts;');
        self::$orm->exec('DROP TABLE IF EXISTS users;');
        self::$orm->exec('DROP TABLE IF EXISTS products;');
    }

    protected static function seedData(): void
    {
        // Seed users
        self::$orm->table('users')->insert(['name' => 'Alice', 'email' => 'alice@example.com', 'status' => 'active']);
        self::$orm->table('users')->insert(['name' => 'Bob', 'email' => 'bob@example.com', 'status' => 'inactive']);
        self::$orm->table('users')->insert(['name' => 'Charlie', 'email' => 'charlie@example.com', 'status' => 'active']);

        // Seed posts
        self::$orm->table('posts')->insert(['user_id' => 1, 'title' => 'Alice Post 1', 'content' => 'Content 1']);
        self::$orm->table('posts')->insert(['user_id' => 1, 'title' => 'Alice Post 2', 'content' => 'Content 2']);
        self::$orm->table('posts')->insert(['user_id' => 2, 'title' => 'Bob Post 1', 'content' => 'Content 3']);

        // Seed products
        self::$orm->table('products')->insert(['sku' => 'P001', 'name' => 'Laptop', 'price' => 1200.50, 'stock' => 10]);
        self::$orm->table('products')->insert(['sku' => 'P002', 'name' => 'Mouse', 'price' => 25.00, 'stock' => 100]);
    }
}