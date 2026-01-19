<?php

declare(strict_types=1);

/**
 * VersaORM Performance Benchmark Script
 * Mide tiempo y memoria en operaciones típicas para identificar hotspots.
 */

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\VersaORM;
use VersaORM\VersaModel;

class PerformanceBenchmark
{
    private VersaORM $orm;
    private array $results = [];

    public function __construct()
    {
        // Configurar ORM con SQLite en memoria para benchmarks rápidos
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => false,
        ]);

        VersaModel::setORM($this->orm);
    }

    public function run(): void
    {
        echo "\n" . str_repeat('=', 80) . "\n";
        echo "🚀 VersaORM Performance Benchmark - " . date('Y-m-d H:i:s') . "\n";
        echo str_repeat('=', 80) . "\n\n";

        $this->setupSchema();

        echo "📊 Ejecutando benchmarks...\n";
        echo str_repeat('-', 80) . "\n\n";

        // Fase 1: Operaciones Básicas
        $this->benchmarkInsertSimple();
        $this->benchmarkInsertMany();
        $this->benchmarkSelectSimple();
        $this->benchmarkSelectWithWhere();
        $this->benchmarkSelectWithJoin();

        // Fase 2: Hidratación y Casting
        $this->benchmarkHydration1000Records();
        $this->benchmarkTypeCasting();

        // Fase 3: QueryBuilder Chains
        $this->benchmarkComplexQuery();

        // Resumen
        $this->printSummary();
    }

    private function setupSchema(): void
    {
        // Crear tabla de usuarios
        $this->orm->exec('
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(255),
                email VARCHAR(255) UNIQUE,
                age INTEGER,
                active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ');

        // Crear tabla de posts
        $this->orm->exec('
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title VARCHAR(255),
                content TEXT,
                published BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ');

        echo "✅ Schema creado (users, posts)\n\n";
    }

    private function benchmarkInsertSimple(): void
    {
        $label = 'INSERT simple (100 registros)';
        $start = microtime(true);
        $memStart = memory_get_usage(true);

        for ($i = 0; $i < 100; $i++) {
            $this->orm->table('users')->insert([
                'name' => "User $i",
                'email' => "user$i@example.com",
                'age' => 20 + ($i % 50),
            ]);
        }

        $this->recordBenchmark($label, $start, $memStart);
    }

    private function benchmarkInsertMany(): void
    {
        $label = 'INSERT many (1000 registros en batch)';
        $start = microtime(true);
        $memStart = memory_get_usage(true);

        $records = [];
        for ($i = 0; $i < 1000; $i++) {
            $records[] = [
                'name' => "BatchUser $i",
                'email' => "batch$i@example.com",
                'age' => 25 + ($i % 40),
            ];
        }

        $this->orm->table('users')->insertMany($records);

        $this->recordBenchmark($label, $start, $memStart);
    }

    private function benchmarkSelectSimple(): void
    {
        $label = 'SELECT simple (get all 1100 users)';
        $start = microtime(true);
        $memStart = memory_get_usage(true);

        $users = $this->orm->table('users')->get();

        $this->recordBenchmark($label, $start, $memStart, count($users));
    }

    private function benchmarkSelectWithWhere(): void
    {
        $label = 'SELECT con WHERE (age > 50, ~200 registros)';
        $start = microtime(true);
        $memStart = memory_get_usage(true);

        $users = $this->orm->table('users')
            ->where('age', '>', 50)
            ->get();

        $this->recordBenchmark($label, $start, $memStart, count($users));
    }

    private function benchmarkSelectWithJoin(): void
    {
        // Primero insertar posts
        $this->orm->table('posts')->insertMany([
            ['user_id' => 1, 'title' => 'Post 1', 'published' => 1],
            ['user_id' => 2, 'title' => 'Post 2', 'published' => 1],
            ['user_id' => 1, 'title' => 'Post 3', 'published' => 0],
        ]);

        $label = 'SELECT con JOIN (users + posts published)';
        $start = microtime(true);
        $memStart = memory_get_usage(true);

        $results = $this->orm->table('users as u')
            ->join('posts as p', 'u.id', '=', 'p.user_id')
            ->where('p.published', '=', 1)
            ->select(['u.name', 'p.title'])
            ->get();

        $this->recordBenchmark($label, $start, $memStart, count($results));
    }

    private function benchmarkHydration1000Records(): void
    {
        $label = 'Hidratación 1100 registros con casting';
        $start = microtime(true);
        $memStart = memory_get_usage(true);

        $users = $this->orm->table('users')
            ->get();

        // Simular acceso a propiedades (como si fueran objetos)
        $count = 0;
        foreach ($users as $user) {
            $name = $user['name'] ?? null;
            $age = (int) ($user['age'] ?? 0);
            $count++;
        }

        $this->recordBenchmark($label, $start, $memStart, $count);
    }

    private function benchmarkTypeCasting(): void
    {
        $label = 'Type Casting (100 casting operations)';
        $start = microtime(true);
        $memStart = memory_get_usage(true);

        $users = $this->orm->table('users')->limit(100)->get();

        $casts = 0;
        foreach ($users as $user) {
            // Simular casting
            (bool) $user['active'];
            (int) $user['age'];
            (string) $user['name'];
            $casts += 3;
        }

        $this->recordBenchmark($label, $start, $memStart, $casts);
    }

    private function benchmarkComplexQuery(): void
    {
        $label = 'Query compleja (WHERE + JOIN + GROUP BY)';
        $start = microtime(true);
        $memStart = memory_get_usage(true);

        $results = $this->orm->table('users as u')
            ->where('u.active', '=', 1)
            ->where('u.age', '>=', 25)
            ->orderBy('u.created_at', 'desc')
            ->limit(50)
            ->get();

        $this->recordBenchmark($label, $start, $memStart, count($results));
    }

    private function recordBenchmark(string $label, float $start, int $memStart, int $itemCount = 0): void
    {
        $elapsed = (microtime(true) - $start) * 1000; // en ms
        $memUsed = (memory_get_usage(true) - $memStart) / 1024 / 1024; // en MB
        $perItem = $itemCount > 0 ? $elapsed / $itemCount : 0;

        $this->results[$label] = [
            'time_ms' => $elapsed,
            'mem_mb' => $memUsed,
            'items' => $itemCount,
            'per_item_ms' => $perItem,
        ];

        $itemStr = '';
        if ($itemCount > 0) {
            $perItemFormatted = number_format($perItem, 4);
            $itemStr = " | {$itemCount} items | {$perItemFormatted}ms/item";
        }
        printf("✓ %-50s | %7.2f ms | %6.2f MB%s\n", $label, $elapsed, $memUsed, $itemStr);
    }

    private function printSummary(): void
    {
        echo "\n" . str_repeat('=', 80) . "\n";
        echo "📈 Resumen de Benchmarks\n";
        echo str_repeat('=', 80) . "\n\n";

        $totalTime = array_sum(array_column($this->results, 'time_ms'));
        $totalMem = array_sum(array_column($this->results, 'mem_mb'));

        echo "Total de tests: " . count($this->results) . "\n";
        echo "Tiempo total: " . number_format($totalTime, 2) . " ms\n";
        echo "Memoria total: " . number_format($totalMem, 2) . " MB\n";

        echo "\n📊 Top 3 operaciones más lentas:\n";
        $sorted = $this->results;
        uasort($sorted, fn($a, $b) => $b['time_ms'] <=> $a['time_ms']);
        $i = 1;
        foreach (array_slice($sorted, 0, 3) as $label => $data) {
            printf("%d. %s: %.2f ms\n", $i++, $label, $data['time_ms']);
        }

        echo "\n✅ Benchmark completado.\n\n";
    }
}

// Ejecutar benchmark
try {
    $benchmark = new PerformanceBenchmark();
    $benchmark->run();
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
    exit(1);
}
