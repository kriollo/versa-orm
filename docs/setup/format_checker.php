<?php
/**
 * Verificador de Consistencia de Formato para Documentación VersaORM
 *
 * Este scriptca que toda la documentación siga las mismas
 * convenciones de formato y estilo.
 */

declare(strict_types=1);

class FormatChecker
{
    private string $docsPath;
    private array $formatRules;
    private array $issues = [];

    public function __construct()
    {
        $this->docsPath = __DIR__ . '/..';
        $this->initializeFormatRules();
    }

    /**
     * Inicializa las reglas de formato
     */
    private function initializeFormatRules(): void
    {
        $this->formatRules = [
            'title_structure' => [
                'pattern' => '/^# [A-ZÁÉÍÓÚÑ]/',
                'message' => 'El título principal debe empezar con "# " y mayúscula'
            ],
            'subtitle_structure' => [
                'pattern' => '/^## [A-ZÁÉÍÓÚÑ]/',
                'message' => 'Los subtítulos deben empezar con "## " y mayúscula'
            ],
            'code_block_php' => [
                'pattern' => '/```php\n.*?\n```/s',
                'message' => 'Los bloques de código PHP deben usar ```php'
            ],
            'code_block_sql' => [
                'pattern' => '/```sql\n.*?\n```/s',
                'message' => 'Los bloques de código SQL deben usar ```sql'
            ],
            'return_type_format' => [
                'pattern' => '/\*\*Devuelve:\*\* [A-Z]/',
                'message' => 'El formato debe ser "**Devuelve:** Tipo" con mayúscula'
            ],
            'sql_equivalent_format' => [
                'pattern' => '/\*\*SQL Equivalente:\*\*/',
                'message' => 'Debe usar "**SQL Equivalente:**"'
            ],
            'example_structure' => [
                'pattern' => '/### Ejemplo [a-záéíóúñ]/i',
                'message' => 'Los ejemplos deben usar "### Ejemplo..."'
            ]
        ];
    }

    /**
     * Ejecuta todas las verificaciones de formato
     */
    public function checkAll(): bool
    {
        echo "=== Verificación de Consistencia de Formato ===\n\n";

        $this->checkMarkdownFiles();
        $this->checkCodeExamples();
        $this->checkNavigationConsistency();
        $this->checkImageReferences();

        return $this->generateFormatReport();
    }

    /**
     * Verifica archivos markdown
     */
    private function checkMarkdownFiles(): void
    {
        echo "📝 Verificando archivos markdown...\n";

        $markdownFiles = $this->findMarkdownFiles($this->docsPath);
        $checkedFiles = 0;

        foreach ($markdownFiles as $file) {
            $content = file_get_contents($file);
            $this->checkFileFormat($file, $content);
            $checkedFiles++;
        }

        echo "   Archivos verificados: {$checkedFiles}\n\n";
    }

    /**
     * Verifica el formato de un archivo individual
     */
    private function checkFileFormat(string $file, string $content): void
    {
        $relativePath = $this->getRelativePath($file);

        // Verificar estructura básica
        $this->checkBasicStructure($file, $content);

        // Verificar reglas específicas
        foreach ($this->formatRules as $ruleName => $rule) {
            $this->applyFormatRule($file, $content, $ruleName, $rule);
        }

        // Verificaciones específicas por tipo de archivo
        if (str_contains($file, 'README.md')) {
            $this->checkReadmeFormat($file, $content);
        } else {
            $this->checkContentFileFormat($file, $content);
        }
    }

    /**
     * Verifica estructura básica del archivo
     */
    private function checkBasicStructure(string $file, string $content): void
    {
        $lines = explode("\n", $content);

        // Verificar que no esté vacío
        if (trim($content) === '') {
            $this->addIssue($file, 'Archivo vacío');
            return;
        }

        // Verificar título principal
        if (!preg_match('/^# /', $lines[0])) {
            $this->addIssue($file, 'Falta título principal (# ) en la primera línea');
        }

        // Verificar líneas en blanco excesivas
        $emptyLineCount = 0;
        foreach ($lines as $line) {
            if (trim($line) === '') {
                $emptyLineCount++;
                if ($emptyLineCount > 2) {
                    $this->addIssue($file, 'Más de 2 líneas en blanco consecutivas');
                    break;
                }
            } else {
                $emptyLineCount = 0;
            }
        }

        // Verificar espacios al final de líneas
        foreach ($lines as $lineNum => $line) {
            if (preg_match('/\s+$/', $line)) {
                $this->addIssue($file, "Espacios al final de la línea " . ($lineNum + 1));
                break; // Solo reportar el primero
            }
        }
    }

    /**
     * Aplica una regla de formato específica
     */
    private function applyFormatRule(string $file, string $content, string $ruleName, array $rule): void
    {
        switch ($ruleName) {
            case 'title_structure':
                if (!preg_match($rule['pattern'], $content)) {
                    $this->addIssue($file, $rule['message']);
                }
                break;

            case 'return_type_format':
                if (str_contains($content, '**Devuelve:**')) {
                    if (!preg_match($rule['pattern'], $content)) {
                        $this->addIssue($file, $rule['message']);
                    }
                }
                break;

            case 'sql_equivalent_format':
                if (str_contains($content, 'SQL Equivalente') &&
                    !preg_match($rule['pattern'], $content)) {
                    $this->addIssue($file, $rule['message']);
                }
                break;

            case 'code_block_php':
                // Verificar que los bloques PHP estén bien formateados
                preg_match_all('/```(\w+)?\n(.*?)\n```/s', $content, $matches);
                foreach ($matches[1] as $index => $lang) {
                    $code = $matches[2][$index];
                    if (str_contains($code, '<?php') && $lang !== 'php') {
                        $this->addIssue($file, 'Bloque de código PHP sin etiqueta ```php');
                    }
                }
                break;
        }
    }

    /**
     * Verifica formato específico de archivos README
     */
    private function checkReadmeFormat(string $file, string $content): void
    {
        // Los README deben tener sección de navegación
        if (!str_contains($content, '##') && !str_contains($content, 'Contenido')) {
            $this->addIssue($file, 'README debería tener secciones de navegación');
        }

        // Verificar enlaces a otros archivos
        preg_match_all('/\[([^\]]+)\]\(([^)]+\.md)\)/', $content, $matches);
        foreach ($matches[2] as $linkedFile) {
            $fullPath = dirname($file) . '/' . $linkedFile;
            if (!file_exists($fullPath)) {
                $this->addIssue($file, "Enlace roto: {$linkedFile}");
            }
        }
    }

    /**
     * Verifica formato específico de archivos de contenido
     */
    private function checkContentFileFormat(string $file, string $content): void
    {
        // Los archivos de contenido deben tener ejemplos de código
        if (!str_contains($content, '```php') &&
            !str_contains($file, 'tipos-relaciones.md') &&
            !str_contains($file, 'que-es-orm.md')) {
            $this->addIssue($file, 'Archivo de contenido sin ejemplos de código PHP');
        }

        // Verificar estructura de ejemplos
        if (str_contains($content, '```php')) {
            $this->checkExampleStructure($file, $content);
        }
    }

    /**
     * Verifica la estructura de los ejemplos
     */
    private function checkExampleStructure(string $file, string $content): void
    {
        // Buscar bloques PHP seguidos de explicación
        preg_match_all('/```php\n(.*?)\n```\s*\n\s*\*\*SQL Equivalente:\*\*/s', $content, $matches);

        if (count($matches[0]) === 0 && str_contains($content, '```php')) {
            // Hay código PHP pero no sigue el formato estándar
            preg_match_all('/```php\n(.*?)\n```/s', $content, $phpBlocks);
            if (count($phpBlocks[0]) > 0) {
                $hasReturnType = str_contains($content, '**Devuelve:**');
                if (!$hasReturnType) {
                    $this->addIssue($file, 'Ejemplos de código sin información de tipo de retorno');
                }
            }
        }
    }

    /**
     * Verifica ejemplos de código
     */
    private function checkCodeExamples(): void
    {
        echo "💻 Verificando ejemplos de código...\n";

        $markdownFiles = $this->findMarkdownFiles($this->docsPath);
        $totalExamples = 0;
        $validExamples = 0;

        foreach ($markdownFiles as $file) {
            $content = file_get_contents($file);
            $examples = $this->extractCodeExamples($content);

            foreach ($examples as $example) {
                $totalExamples++;
                if ($this->validateCodeExample($file, $example)) {
                    $validExamples++;
                }
            }
        }

        echo "   Ejemplos verificados: {$validExamples}/{$totalExamples}\n\n";
    }

    /**
     * Extrae ejemplos de código de un archivo
     */
    private function extractCodeExamples(string $content): array
    {
        $examples = [];
        preg_match_all('/```php\n(.*?)\n```/s', $content, $matches);

        foreach ($matches[1] as $code) {
            $examples[] = $code;
        }

        return $examples;
    }

    /**
     * Valida un ejemplo de código individual
     */
    private function validateCodeExample(string $file, string $code): bool
    {
        // Verificar sintaxis básica
        if (!str_contains($code, '$')) {
            $this->addIssue($file, 'Ejemplo de código sin variables PHP');
            return false;
        }

        // Verificar que use VersaORM
        if (!str_contains($code, '$orm') && !str_contains($code, 'VersaORM')) {
            $this->addIssue($file, 'Ejemplo de código que no usa VersaORM');
            return false;
        }

        // Verificar comentarios explicativos
        if (!str_contains($code, '//') && strlen($code) > 100) {
            $this->addIssue($file, 'Ejemplo complejo sin comentarios explicativos');
            return false;
        }

        return true;
    }

    /**
     * Verifica consistencia de navegación
     */
    private function checkNavigationConsistency(): void
    {
        echo "🧭 Verificando navegación...\n";

        $mainReadme = $this->docsPath . '/README.md';
        if (!file_exists($mainReadme)) {
            $this->addIssue($mainReadme, 'Falta README.md principal');
            return;
        }

        $mainContent = file_get_contents($mainReadme);
        $directories = $this->getDocumentationDirectories();

        foreach ($directories as $dir) {
            $dirName = basename($dir);
            if (!str_contains($mainContent, $dirName)) {
                $this->addIssue($mainReadme, "Falta enlace a directorio: {$dirName}");
            }
        }

        echo "   Navegación verificada\n\n";
    }

    /**
     * Verifica referencias a imágenes
     */
    private function checkImageReferences(): void
    {
        echo "🖼️  Verificando referencias a imágenes...\n";

        $markdownFiles = $this->findMarkdownFiles($this->docsPath);
        $imageReferences = 0;
        $brokenImages = 0;

        foreach ($markdownFiles as $file) {
            $content = file_get_contents($file);
            preg_match_all('/!\[([^\]]*)\]\(([^)]+)\)/', $content, $matches);

            foreach ($matches[2] as $imagePath) {
                $imageReferences++;
                $fullImagePath = dirname($file) . '/' . $imagePath;

                if (!file_exists($fullImagePath)) {
                    $brokenImages++;
                    $this->addIssue($file, "Imagen no encontrada: {$imagePath}");
                }
            }
        }

        echo "   Referencias verificadas: {$imageReferences}, rotas: {$brokenImages}\n\n";
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
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Obtiene directorios de documentación
     */
    private function getDocumentationDirectories(): array
    {
        $directories = [];
        $items = scandir($this->docsPath);

        foreach ($items as $item) {
            if ($item !== '.' && $item !== '..' &&
                is_dir($this->docsPath . '/' . $item) &&
                preg_match('/^\d{2}-/', $item)) {
                $directories[] = $this->docsPath . '/' . $item;
            }
        }

        return $directories;
    }

    /**
     * Agrega un problema encontrado
     */
    private function addIssue(string $file, string $message): void
    {
        $this->issues[] = [
            'file' => $this->getRelativePath($file),
            'message' => $message
        ];
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

    /**
     * Genera reporte de formato
     */
    private function generateFormatReport(): bool
    {
        echo "=== REPORTE DE FORMATO ===\n\n";

        $totalIssues = count($this->issues);

        if ($totalIssues === 0) {
            echo "✅ ¡Formato perfecto!\n";
            echo "   Toda la documentación sigue las convenciones establecidas.\n";
            return true;
        }

        echo "⚠️  Problemas de formato encontrados: {$totalIssues}\n\n";

        // Agrupar por archivo
        $issuesByFile = [];
        foreach ($this->issues as $issue) {
            $issuesByFile[$issue['file']][] = $issue['message'];
        }

        foreach ($issuesByFile as $file => $messages) {
            echo "📄 {$file}:\n";
            foreach ($messages as $message) {
                echo "   - {$message}\n";
            }
            echo "\n";
        }

        // Guardar reporte
        $reportFile = __DIR__ . '/format_report.json';
        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'total_issues' => $totalIssues,
            'issues_by_file' => $issuesByFile,
            'format_rules' => array_keys($this->formatRules)
        ];

        file_put_contents($reportFile, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        echo "📄 Reporte detallado guardado en: format_report.json\n";

        return false;
    }
}

// Ejecutar verificación si se llama directamente
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    $checker = new FormatChecker();
    $success = $checker->checkAll();
    exit($success ? 0 : 1);
}
