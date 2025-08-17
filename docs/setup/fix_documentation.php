<?php
/**
 * Script para corregir automáticamente la documentación de VersaORM
 *
 * Este script aplica correcciones masivas para actualizar la documentación
 * con la sintaxis correcta de VersaORM basada en los tests.
 */

declare(strict_types=1);

class DocumentationFixer
{
    private array $corrections = [];
    private string $docsPath;
    private int $filesFixed = 0;
    private int $replacementsMade = 0;

    public function __construct()
    {
        $this->docsPath = __DIR__ . '/..';
        $this->initializeCorrections();
    }

    /**
     * Inicializa las correcciones a aplicar
     */
    private function initializeCorrections(): void
    {
        $this->corrections = [
            // Correcciones de VersaModel
            '$orm->dispense(' => 'VersaModel::dispense(',
            '$orm->load(' => 'VersaModel::load(',
            '$orm->store(' => '$model->store(',
            '$orm->trash(' => '$model->trash(',
            '$orm->find(' => 'VersaModel::findAll(',
            '$orm->findOne(' => 'VersaModel::findOne(',
            '$orm->storeAll(' => 'VersaModel::storeAll(',
            '$orm->trashAll(' => 'VersaModel::trashAll(',

            // Correcciones de QueryBuilder
            '->getOne()' => '->firstArray()',

            // Correcciones de verificación de existencia
            'if ($usuario->id)' => 'if ($usuario !== null)',
            'if (!$usuario->id)' => 'if ($usuario === null)',
            'if ($model->id)' => 'if ($model !== null)',
            'if (!$model->id)' => 'if ($model === null)',

            // Correcciones de transacciones
            '$orm->begin()' => '$orm->exec(\'BEGIN\')',
            '$orm->commit()' => '$orm->exec(\'COMMIT\')',
            '$orm->rollback()' => '$orm->exec(\'ROLLBACK\')',

            // Correcciones de métodos no existentes
            '->sum(' => '// ->sum( // Método no disponible en VersaORM',
            '->avg(' => '// ->avg( // Método no disponible en VersaORM',
            '->min(' => '// ->min( // Método no disponible en VersaORM',
            '->max(' => '// ->max( // Método no disponible en VersaORM',

            // Correcciones de select
            "->select('" => "->select(['",
            "', '" => "', '",
            "')" => "'])",

            // Correcciones de configuración
            'VersaModel::setORM($orm);' => '// VersaModel::setORM($orm); // Ya configurado',
        ];
    }

    /**
     * Ejecuta todas las correcciones
     */
    public function fixAll(): void
    {
        echo "🔧 Iniciando corrección automática de documentación...\n\n";

        $markdownFiles = $this->findMarkdownFiles($this->docsPath);

        foreach ($markdownFiles as $file) {
            $this->fixFile($file);
        }

        echo "\n✅ Corrección completada:\n";
        echo "   - Archivos procesados: " . count($markdownFiles) . "\n";
        echo "   - Archivos modificados: {$this->filesFixed}\n";
        echo "   - Reemplazos realizados: {$this->replacementsMade}\n";
    }

    /**
     * Corrige un archivo individual
     */
    private function fixFile(string $file): void
    {
        $content = file_get_contents($file);
        $originalContent = $content;
        $fileReplacements = 0;

        // Aplicar correcciones específicas para bloques de código PHP
        $content = preg_replace_callback(
            '/```php\n(.*?)\n```/s',
            function ($matches) use (&$fileReplacements) {
                $code = $matches[1];
                $originalCode = $code;

                // Aplicar correcciones al código
                foreach ($this->corrections as $search => $replace) {
                    $newCode = str_replace($search, $replace, $code);
                    if ($newCode !== $code) {
                        $fileReplacements += substr_count($code, $search);
                        $code = $newCode;
                    }
                }

                // Correcciones específicas adicionales
                $code = $this->applySpecificCorrections($code);

                return "```php\n" . $code . "\n```";
            },
            $content
        );

        // Aplicar correcciones a texto fuera de bloques de código
        $content = $this->fixDocumentationText($content);

        // Guardar archivo si hubo cambios
        if ($content !== $originalContent) {
            file_put_contents($file, $content);
            $this->filesFixed++;
            $this->replacementsMade += $fileReplacements;

            $relativePath = $this->getRelativePath($file);
            echo "📝 Corregido: {$relativePath} ({$fileReplacements} cambios)\n";
        }
    }

    /**
     * Aplica correcciones específicas al código PHP
     */
    private function applySpecificCorrections(string $code): string
    {
        // Corregir configuración de VersaModel
        if (str_contains($code, 'new VersaORM(') && !str_contains($code, 'VersaModel::setORM')) {
            $code = str_replace(
                ']);',
                ']);\n    VersaModel::setORM($orm);',
                $code
            );
        }

        // Corregir verificaciones de existencia más complejas
        $code = preg_replace(
            '/if\s*\(\s*\$\w+->id\s*\)\s*{/',
            'if ($model !== null) {',
            $code
        );

        // Corregir llamadas a métodos en modelos
        $code = preg_replace(
            '/\$orm->store\(\$(\w+)\);/',
            '$$1->store();',
            $code
        );

        $code = preg_replace(
            '/\$orm->trash\(\$(\w+)\);/',
            '$$1->trash();',
            $code
        );

        // Corregir select con strings
        $code = preg_replace(
            '/->select\([\'"]([^\'"]+)[\'"]\)/',
            "->select(['$1'])",
            $code
        );

        return $code;
    }

    /**
     * Corrige texto de documentación fuera de bloques de código
     */
    private function fixDocumentationText(string $content): string
    {
        // Corregir descripciones de métodos
        $textCorrections = [
            'Objeto VersaModel (vacío si no existe)' => 'Objeto VersaModel o null si no existe',
            'El ID del registro creado (integer)' => 'El modelo almacenado con ID asignado',
            'Array de IDs de los registros creados' => 'Array de modelos almacenados con IDs asignados',
            'El ID del registro actualizado (integer)' => 'El modelo actualizado',
        ];

        foreach ($textCorrections as $search => $replace) {
            $content = str_replace($search, $replace, $content);
        }

        return $content;
    }

    /**
     * Encuentra todos los archivos markdown
     */
    private function findMarkdownFiles(string $dir): array
    {
        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'md') {
                // Excluir archivos de setup
                if (!str_contains($file->getPathname(), '/setup/')) {
                    $files[] = $file->getPathname();
                }
            }
        }

        return $files;
    }

    /**
     * Obtiene la ruta relativa de un archivo
     */
    private function getRelativePath(string $file): string
    {
        $docsPath = realpath($this->docsPath);
        $filePath = realpath($file);

        if ($filePath && str_starts_with($filePath, $docsPath)) {
            return 'docs' . substr($filePath, strlen($docsPath));
        }

        return basename($file);
    }
}

// Ejecutar corrección si se llama directamente
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    $fixer = new DocumentationFixer();
    $fixer->fixAll();
}
