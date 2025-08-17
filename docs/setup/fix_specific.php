<?php
/**
 * Script para correcciones específicas
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

    // Correcciones específicas
    $content = preg_replace_callback(
        '/```php\n(.*?)\n```/s',
        function ($matches) {
            $code = $matches[1];

            // Si es un ejemplo simple que usa VersaModel, agregar contexto
            if (str_contains($code, 'VersaModel::') && !str_contains($code, '<?php') && !str_contains($code, '//')) {
                $code = "// Asumiendo que VersaModel ya está configurado\n" . $code;
            }

            // Corregir ejemplos que usan tablas en español
            $code = str_replace("'usuario'", "'users'", $code);
            $code = str_replace("'producto'", "'products'", $code);
            $code = str_replace("'usuarios'", "'users'", $code);
            $code = str_replace("'productos'", "'products'", $code);

            // Corregir propiedades en español
            $code = str_replace('->nombre', '->name', $code);
            $code = str_replace('->precio', '->price', $code);
            $code = str_replace('->activo', '->active', $code);

            // Corregir métodos que no existen
            $code = str_replace('->sum(', '// ->sum( // Método no disponible', $code);
            $code = str_replace('->avg(', '// ->avg( // Método no disponible', $code);
            $code = str_replace('->min(', '// ->min( // Método no disponible', $code);
            $code = str_replace('->max(', '// ->max( // Método no disponible', $code);

            return "```php\n" . $code . "\n```";
        },
        $content
    );

    if ($content !== $originalContent) {
        file_put_contents($file, $content);
        $totalFixed++;
        echo "Corregido específicamente: " . basename($file) . "\n";
    }
}

echo "\nTotal de archivos con correcciones específicas: $totalFixed\n";
