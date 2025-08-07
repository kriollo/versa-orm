<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use PHPUnit\Framework\TestCase as BaseTestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

require_once __DIR__ . '/bootstrap.php';

class TestCase extends BaseTestCase
{
    public static ?VersaORM $orm = null;
    private static bool $schemaCreated = false;

    public static function setUpBeforeClass(): void
    {
        if (self::$orm === null) {
            global $config;
            $dbConfig = [
                'driver' => $config['DB']['DB_DRIVER'],
                'database' => $config['DB']['DB_NAME'],
                'debug' => $config['DB']['debug'],
                'host' => $config['DB']['DB_HOST'] ?? '',
                'port' => $config['DB']['DB_PORT'] ?? 0,
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
        // Limpia las tablas después de cada test
        self::$orm->exec('DROP TABLE IF EXISTS posts CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS profiles CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS role_user CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS roles CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS users CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS products CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS test_users CASCADE;');
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$schemaCreated) {
            self::$schemaCreated = false;
        }
        self::$orm = null;
    }

    protected static function createSchema(): void
    {
        self::dropSchema(); // Ensure clean state before creating

        // Configuración específica para PostgreSQL
        global $config;
        if ($config['DB']['DB_DRIVER'] === 'postgresql') {
            // PostgreSQL no necesita configuraciones especiales como MySQL
        }

        // Crear tabla users con sintaxis PostgreSQL
        self::$orm->exec('
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(191) UNIQUE NOT NULL DEFAULT \'\',
                status VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ');

        // Crear tabla profiles
        self::$orm->exec('
            CREATE TABLE profiles (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                bio TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        ');

        // Crear tabla posts
        self::$orm->exec('
            CREATE TABLE posts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                title VARCHAR(255) NOT NULL,
                content TEXT,
                published_at TIMESTAMP NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        ');

        // Crear tabla roles
        self::$orm->exec('
            CREATE TABLE roles (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL
            );
        ');

        // Crear tabla role_user (pivot table)
        self::$orm->exec('
            CREATE TABLE role_user (
                user_id INTEGER,
                role_id INTEGER,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
            );
        ');

        // Crear tabla products
        self::$orm->exec('
            CREATE TABLE products (
                sku VARCHAR(50) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                price DECIMAL(10, 2) NULL,
                stock INTEGER DEFAULT 0,
                description TEXT NULL,
                category VARCHAR(100) NULL
            );
        ');
    }

    protected static function dropSchema(): void
    {
        // Usar CASCADE para eliminar dependencias en PostgreSQL
        self::$orm->exec('DROP TABLE IF EXISTS posts CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS profiles CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS role_user CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS roles CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS users CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS products CASCADE;');
        self::$orm->exec('DROP TABLE IF EXISTS test_users CASCADE;');
    }

    protected static function seedData(): void
    {
        // Seed users (PostgreSQL SERIAL maneja el AUTO_INCREMENT)
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
