<?php
/**
 * Script para agregar imports necesarios a los ejemplos de código
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

    // Buscar bloques de código PHP que usan VersaModel pero no lo importan
    $content = preg_replace_callback(
        '/```php\n(.*?)\n```/s',
        function ($matches) {
            $code = $matches[1];

            // Si usa VersaModel pero no tiene import
            if (str_contains($code, 'VersaModel::') && !str_contains($code, 'use VersaORM\VersaModel')) {
                // Agregar import al inicio
                if (str_contains($code, '<?php')) {
                    $code = str_replace('<?php', "<?php\nuse VersaORM\VersaModel;", $code);
                } else {
                    $code = "use VersaORM\VersaModel;\n\n" . $code;
                }
            }

            // Si usa VersaORM pero no lo importa
            if (str_contains($code, 'new VersaORM(') && !str_contains($code, 'use VersaORM\VersaORM')) {
                if (str_contains($code, 'use VersaORM\VersaModel;')) {
                    $code = str_replace('use VersaORM\VersaModel;', "use VersaORM\VersaORM;\nuse VersaORM\VersaModel;", $code);
                } else if (str_contains($code, '<?php')) {
                    $code = str_replace('<?php', "<?php\nuse VersaORM\VersaORM;", $code);
                } else {
                    $code = "use VersaORM\VersaORM;\n\n" . $code;
                }
            }

            return "```php\n" . $code . "\n```";
        },
        $content
    );

    if ($content !== $originalContent) {
        file_put_contents($file, $content);
        $totalFixed++;
        echo "Agregados imports: " . basename($file) . "\n";
    }
}

echo "\nTotal de archivos con imports agregados: $totalFixed\n";
