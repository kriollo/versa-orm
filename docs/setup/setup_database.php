<?php

/**
 * Script de configuración inicial para ejemplos de VersaORM
 *
 * Este script crea las tablas de ejemplo y datos de prueba
 * utilizados en toda la documentación.
 */

require_once __DIR__.'/../../vendor/autoload.php';

use VersaORM\VersaModel;
use VersaORM\VersaORM;

class DatabaseSetup extends VersaModel
{
    private $orm;

    private $config;

    public function __construct()
    {
        $this->loadConfig();
        $this->initializeORM();
    }

    private function loadConfig()
    {
        $configFile = __DIR__.'/database_config.php';
        if (file_exists($configFile)) {
            $this->config = require $configFile;
        } else {
            // Configuración por defecto para SQLite
            $this->config = [
                'driver' => 'sqlite',
                'database' => __DIR__.'/../../docs_examples.sqlite',
                'host' => '',
                'username' => '',
                'password' => '',
                'charset' => 'utf8mb4',
            ];
        }
    }

    private function initializeORM()
    {
        try {
            $this->orm = new VersaORM($this->config);
            echo "✓ Conexión a base de datos establecida\n";
        } catch (Exception $e) {
            exit('✗ Error conectando a la base de datos: '.$e->getMessage()."\n");
        }
    }

    public function createTables()
    {
        echo "Creando tablas de ejemplo...\n";

        // Tabla users
        $this->orm->exec('
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ');
        echo "✓ Tabla 'users' creada\n";

        // Tabla posts
        $this->orm->exec('
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title VARCHAR(200) NOT NULL,
                content TEXT,
                user_id INTEGER,
                published BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ');
        echo "✓ Tabla 'posts' creada\n";

        // Tabla tags
        $this->orm->exec('
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(50) NOT NULL UNIQUE
            )
        ');
        echo "✓ Tabla 'tags' creada\n";

        // Tabla post_tags (many-to-many)
        $this->orm->exec('
            CREATE TABLE IF NOT EXISTS post_tags (
                post_id INTEGER,
                tag_id INTEGER,
                PRIMARY KEY (post_id, tag_id),
                FOREIGN KEY (post_id) REFERENCES posts(id),
                FOREIGN KEY (tag_id) REFERENCES tags(id)
            )
        ');
        echo "✓ Tabla 'post_tags' creada\n";
    }

    public function insertSampleData()
    {
        echo "Insertando datos de ejemplo...\n";

        // Limpiar datos existentes
        $this->orm->exec('DELETE FROM post_tags');
        $this->orm->exec('DELETE FROM posts');
        $this->orm->exec('DELETE FROM tags');
        $this->orm->exec('DELETE FROM users');

        // Usuarios de ejemplo
        $users = [
            ['name' => 'Juan Pérez', 'email' => 'juan@ejemplo.com', 'active' => 1],
            ['name' => 'María García', 'email' => 'maria@ejemplo.com', 'active' => 1],
            ['name' => 'Carlos López', 'email' => 'carlos@ejemplo.com', 'active' => 0],
            ['name' => 'Ana Martínez', 'email' => 'ana@ejemplo.com', 'active' => 1],
        ];

        versaModel::setORM($this->orm);

        foreach ($users as $userData) {
            $user = $this->dispense('users');
            $user->name = $userData['name'];
            $user->email = $userData['email'];
            $user->active = $userData['active'];
            $user->store();
        }
        echo "✓ Usuarios insertados\n";

        // Posts de ejemplo
        $posts = [
            ['title' => 'Introducción a PHP', 'content' => 'PHP es un lenguaje de programación...', 'user_id' => 1, 'published' => 1],
            ['title' => 'Bases de datos con MySQL', 'content' => 'MySQL es un sistema de gestión...', 'user_id' => 1, 'published' => 1],
            ['title' => 'Desarrollo web moderno', 'content' => 'El desarrollo web ha evolucionado...', 'user_id' => 2, 'published' => 1],
            ['title' => 'Borrador: Nuevas características', 'content' => 'Este es un borrador...', 'user_id' => 2, 'published' => 0],
            ['title' => 'Guía de JavaScript', 'content' => 'JavaScript es el lenguaje...', 'user_id' => 4, 'published' => 1],
        ];

        foreach ($posts as $postData) {
            $post = $this->dispense('posts');
            $post->title = $postData['title'];
            $post->content = $postData['content'];
            $post->user_id = $postData['user_id'];
            $post->published = $postData['published'];
            $post->store();
        }
        echo "✓ Posts insertados\n";

        // Tags de ejemplo
        $tags = [
            ['name' => 'PHP'],
            ['name' => 'MySQL'],
            ['name' => 'JavaScript'],
            ['name' => 'Web Development'],
            ['name' => 'Tutorial'],
            ['name' => 'Beginner'],
        ];

        foreach ($tags as $tagData) {
            $tag = $this->dispense('tags');
            $tag->name = $tagData['name'];
            $tag->store();
        }
        echo "✓ Tags insertados\n";

        // Relaciones post_tags
        $postTags = [
            ['post_id' => 1, 'tag_id' => 1], // Introducción a PHP -> PHP
            ['post_id' => 1, 'tag_id' => 5], // Introducción a PHP -> Tutorial
            ['post_id' => 1, 'tag_id' => 6], // Introducción a PHP -> Beginner
            ['post_id' => 2, 'tag_id' => 1], // Bases de datos -> PHP
            ['post_id' => 2, 'tag_id' => 2], // Bases de datos -> MySQL
            ['post_id' => 3, 'tag_id' => 4], // Desarrollo web -> Web Development
            ['post_id' => 5, 'tag_id' => 3], // JavaScript -> JavaScript
            ['post_id' => 5, 'tag_id' => 4], // JavaScript -> Web Development
        ];

        foreach ($postTags as $relation) {
            $this->orm->exec(
                'INSERT INTO post_tags (post_id, tag_id) VALUES (?, ?)',
                [$relation['post_id'], $relation['tag_id']]
            );
        }
        echo "✓ Relaciones post-tags insertadas\n";
    }

    public function showSummary()
    {
        echo "\n=== RESUMEN DE LA BASE DE DATOS ===\n";

        $userCount = $this->getCell('SELECT COUNT(*) FROM users');
        $postCount = $this->getCell('SELECT COUNT(*) FROM posts');
        $tagCount = $this->getCell('SELECT COUNT(*) FROM tags');
        $relationCount = $this->getCell('SELECT COUNT(*) FROM post_tags');

        echo "Usuarios: $userCount\n";
        echo "Posts: $postCount\n";
        echo "Tags: $tagCount\n";
        echo "Relaciones post-tag: $relationCount\n";

        echo "\n=== USUARIOS DE EJEMPLO ===\n";
        $users = $this->getAll('SELECT id, name, email, active FROM users ORDER BY id');
        foreach ($users as $user) {
            $status = $user['active'] ? 'Activo' : 'Inactivo';
            echo "ID: {$user['id']} | {$user['name']} | {$user['email']} | $status\n";
        }

        echo "\n=== POSTS DE EJEMPLO ===\n";
        $posts = $this->getAll('
            SELECT p.id, p.title, u.name as author, p.published
            FROM posts p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.id
        ');
        foreach ($posts as $post) {
            $status = $post['published'] ? 'Publicado' : 'Borrador';
            echo "ID: {$post['id']} | {$post['title']} | Autor: {$post['author']} | $status\n";
        }

        echo "\n✓ Base de datos configurada correctamente\n";
        echo "Puedes comenzar a usar los ejemplos de la documentación.\n";
    }

    public function run()
    {
        try {
            $this->createTables();
            $this->insertSampleData();
            $this->showSummary();
        } catch (Exception $e) {
            echo '✗ Error durante la configuración: '.$e->getMessage()."\n";
            var_dump($e->getTraceAsString());
            exit(1);
        }
    }
}

// Ejecutar configuración
echo "=== CONFIGURACIÓN DE BASE DE DATOS PARA EJEMPLOS ===\n\n";

$setup = new DatabaseSetup();
$setup->run();
