<?php
/**
 * Script simple para corregir la documentación
 */

$docsPath = __DIR__ . '/..';

// Encontrar archivos markdown
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

    // Correcciones básicas
    $content = str_replace('$orm->dispense(', 'VersaModel::dispense(', $content);
    $content = str_replace('$orm->load(', 'VersaModel::load(', $content);
    $content = str_replace('$orm->find(', 'VersaModel::findAll(', $content);
    $content = str_replace('$orm->findOne(', 'VersaModel::findOne(', $content);
    $content = str_replace('->getOne()', '->firstArray()', $content);

    // Correcciones de store y trash
    $content = preg_replace('/\$orm->store\(\$(\w+)\)/', '$$$1->store()', $content);
    $content = preg_replace('/\$orm->trash\(\$(\w+)\)/', '$$$1->trash()', $content);

    // Correcciones de verificación de existencia
    $content = preg_replace('/if\s*\(\s*\$\w+->id\s*\)/', 'if ($model !== null)', $content);
    $content = preg_replace('/if\s*\(\s*!\$\w+->id\s*\)/', 'if ($model === null)', $content);

    if ($content !== $originalContent) {
        file_put_contents($file, $content);
        $totalFixed++;
        echo "Corregido: " . basename($file) . "\n";
    }
}

echo "\nTotal de archivos corregidos: $totalFixed\n";
