<?php
/**
 * Script para corregir todas las configuraciones incorrectas de VersaORM
 */

$docsPath = __DIR__ . '/..';

function findMarkdownFiles($dir) {
    $files = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));

    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === 'md' && !str_contains($file->getPathname(), '/setup/')) {
            $files[] = $file->getPathname();
        }
    }
    return $files;
}

$files = findMarkdownFiles($docsPath);
$totalFixed = 0;

foreach ($files as $file) {
    $content = file_get_contents($file);
    $originalContent = $content;

    // Corregir configuraciones incorrectas

    // 1. Configuración estilo PDO (incorrecta)
    $content = preg_replace(
        '/new VersaORM\([\'"]mysql:host=([^;]+);dbname=([^\'\"]+)[\'"],\s*[\'"]?([^\'\"]*)[\'"]?,\s*[\'"]?([^\'\"]*)[\'"]?\)/',
        'new VersaORM([
    \'engine\' => \'pdo\',
    \'driver\' => \'mysql\',
    \'host\' => \'$1\',
    \'database\' => \'$2\',
    \'username\' => \'$3\',
    \'password\' => \'$4\'
])',
        $content
    );

    // 2. Configuración PostgreSQL estilo PDO
    $content = preg_replace(
        '/new VersaORM\([\'"]pgsql:host=([^;]+);dbname=([^\'\"]+)[\'"],\s*[\'"]?([^\'\"]*)[\'"]?,\s*[\'"]?([^\'\"]*)[\'"]?\)/',
        'new VersaORM([
    \'engine\' => \'pdo\',
    \'driver\' => \'postgresql\',
    \'host\' => \'$1\',
    \'database\' => \'$2\',
    \'username\' => \'$3\',
    \'password\' => \'$4\'
])',
        $content
    );

    // 3. Configuración SQLite estilo PDO
    $content = preg_replace(
        '/new VersaORM\([\'"]sqlite:([^\'\"]+)[\'\"]\)/',
        'new VersaORM([
    \'engine\' => \'pdo\',
    \'driver\' => \'sqlite\',
    \'database\' => \'$1\'
])',
        $content
    );

    // 4. SQLite en memoria
    $content = str_replace(
        "new VersaORM('sqlite::memory:')",
        "new VersaORM([
    'engine' => 'pdo',
    'driver' => 'sqlite',
    'database' => ':memory:'
])"
    );

    // 5. Configuraciones sin parámetros
    $content = str_replace('new VersaORM()', 'new VersaORM([
    \'engine\' => \'pdo\',
    \'driver\' => \'sqlite\',
    \'database\' => \'database.db\'
])');

    // 6. Corregir configuraciones que ya están parcialmente correctas pero les falta engine
    $content = preg_replace(
        '/new VersaORM\(\[\s*\n\s*[\'"]host[\'"]/',
        'new VersaORM([
    \'engine\' => \'pdo\',
    \'driver\' => \'mysql\',
    \'host\'',
        $content
    );

    // 7. Eliminar métodos que no existen como setup()
    $content = preg_replace(
        '/\$orm->setup\([^)]+\);?\s*\n?/',
        '',
        $content
    );

    // 8. Agregar VersaModel::setORM después de crear VersaORM
    $content = preg_replace(
        '/(new VersaORM\(\[[^\]]+\]\);)\s*\n/',
        '$1
VersaModel::setORM($orm);

',
        $content
    );

    if ($content !== $originalContent) {
        file_put_contents($file, $content);
        $totalFixed++;
        echo "Configuración corregida: " . basename($file) . "\n";
    }
}

echo "\nTotal de archivos con configuración corregida: $totalFixed\n";
