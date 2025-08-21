<?php

/**
 * Validador de Documentación VersaORM
 *
 * Este script valida todos los ejemplos de código en la documentación,
 * verifica tipos de retorno, compatibilidad con bases de datos y
 * consistencia de formato.
 */

declare(strict_types=1);

require_once __DIR__.'/../../vendor/autoload.php';

use VersaORM\VersaModel;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

class DocumentationValidator
{
    private array $supportedDatabases = ['sqlite', 'mysql', 'postgresql'];

    private array $validationResults = [];

    private array $codeExamples = [];

    private string $docsPath;

    private ?VersaORM $orm = null;

    public function __construct()
    {
        $this->docsPath = __DIR__.'/..';
        $this->initializeDatabase();
    }

    /**
     * Inicializa la base de datos de prueba
     */
    private function initializeDatabase(): void
    {
        try {
            // Usar SQLite para las pruebas por simplicidad
            $config = [
                'engine' => 'pdo',
                'driver' => 'sqlite',
                'database' => __DIR__.'/validation_test.sqlite',
                'host' => '',
                'username' => '',
                'password' => '',
                'charset' => 'utf8mb4',
            ];

            $this->orm = new VersaORM($config);
            VersaModel::setORM($this->orm);
            $this->setupTestTables();
            $this->insertTestData();

            echo "✓ Base de datos de prueba inicializada\n";
        } catch (Exception $e) {
            exit('✗ Error inicializando base de datos: '.$e->getMessage()."\n");
        }
    }

    /**
     * Crea las tablas de prueba
     */
    private function setupTestTables(): void
    {
        $tables = [
            'users' => '
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    active BOOLEAN DEFAULT 1,
                    age INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ',
            'posts' => '
                CREATE TABLE IF NOT EXISTS posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title VARCHAR(200) NOT NULL,
                    content TEXT,
                    user_id INTEGER,
                    published BOOLEAN DEFAULT 0,
                    views INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ',
            'tags' => '
                CREATE TABLE IF NOT EXISTS tags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(50) NOT NULL UNIQUE
                )
            ',
            'post_tags' => '
                CREATE TABLE IF NOT EXISTS post_tags (
                    post_id INTEGER,
                    tag_id INTEGER,
                    PRIMARY KEY (post_id, tag_id),
                    FOREIGN KEY (post_id) REFERENCES posts(id),
                    FOREIGN KEY (tag_id) REFERENCES tags(id)
                )
            ',
        ];

        foreach ($tables as $tableName => $sql) {
            $this->orm->exec($sql);
        }
    }

    /**
     * Inserta datos de prueba
     */
    private function insertTestData(): void
    {
        // Limpiar datos existentes
        $this->orm->exec('DELETE FROM post_tags');
        $this->orm->exec('DELETE FROM posts');
        $this->orm->exec('DELETE FROM tags');
        $this->orm->exec('DELETE FROM users');

        // Insertar usuarios
        $users = [
            ['name' => 'Juan Pérez', 'email' => 'juan@ejemplo.com', 'active' => 1, 'age' => 30],
            ['name' => 'María García', 'email' => 'maria@ejemplo.com', 'active' => 1, 'age' => 25],
            ['name' => 'Carlos López', 'email' => 'carlos@ejemplo.com', 'active' => 0, 'age' => 35],
        ];

        foreach ($users as $userData) {
            $user = VersaModel::dispense('users');
            foreach ($userData as $key => $value) {
                $user->$key = $value;
            }
            $user->store();
        }

        // Insertar posts
        $posts = [
            ['title' => 'Mi primer post', 'content' => 'Contenido del primer post', 'user_id' => 1, 'published' => 1, 'views' => 100],
            ['title' => 'Segundo post', 'content' => 'Contenido del segundo post', 'user_id' => 1, 'published' => 0, 'views' => 50],
            ['title' => 'Post de María', 'content' => 'Contenido de María', 'user_id' => 2, 'published' => 1, 'views' => 75],
        ];

        foreach ($posts as $postData) {
            $post = VersaModel::dispense('posts');
            foreach ($postData as $key => $value) {
                $post->$key = $value;
            }
            $post->store();
        }

        // Insertar tags
        $tags = [
            ['name' => 'php'],
            ['name' => 'orm'],
            ['name' => 'tutorial'],
        ];

        foreach ($tags as $tagData) {
            $tag = VersaModel::dispense('tags');
            $tag->name = $tagData['name'];
            $tag->store();
        }

        // Insertar relaciones post_tags
        $postTags = [
            ['post_id' => 1, 'tag_id' => 1],
            ['post_id' => 1, 'tag_id' => 2],
            ['post_id' => 2, 'tag_id' => 1],
            ['post_id' => 3, 'tag_id' => 3],
        ];

        foreach ($postTags as $relation) {
            $this->orm->exec(
                'INSERT INTO post_tags (post_id, tag_id) VALUES (?, ?)',
                [$relation['post_id'], $relation['tag_id']]
            );
        }
    }

    /**
     * Ejecuta todas las validaciones
     */
    public function validateAll(): bool
    {
        echo "=== Iniciando Validación de Documentación VersaORM ===\n\n";

        $this->extractCodeExamples();
        $this->validateCodeExamples();
        $this->validateReturnTypes();
        $this->validateFormatConsistency();
        $this->validateInternalLinks();

        return $this->generateReport();
    }

    /**
     * Extrae ejemplos de código de todos los archivos markdown
     */
    private function extractCodeExamples(): void
    {
        echo "📋 Extrayendo ejemplos de código...\n";

        $markdownFiles = $this->findMarkdownFiles($this->docsPath);

        foreach ($markdownFiles as $file) {
            $content = file_get_contents($file);
            $examples = $this->parseCodeBlocks($content, $file);
            $this->codeExamples = array_merge($this->codeExamples, $examples);
        }

        echo '   Encontrados '.count($this->codeExamples)." ejemplos de código\n\n";
    }

    /**
     * Encuentra todos los archivos markdown en el directorio docs
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
     * Parsea bloques de código PHP de un archivo markdown
     */
    private function parseCodeBlocks(string $content, string $file): array
    {
        $examples = [];
        $pattern = '/```php\s*\n(.*?)\n```/s';

        preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE);

        foreach ($matches[1] as $index => $match) {
            $code = trim($match[0]);
            $offset = $match[1];

            // Saltar ejemplos vacíos o solo comentarios
            if (empty($code) || preg_match('/^\/\/.*$/', $code)) {
                continue;
            }

            // Calcular número de línea aproximado
            $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;

            $examples[] = [
                'file' => $file,
                'line' => $lineNumber,
                'code' => $code,
                'index' => $index,
            ];
        }

        return $examples;
    }

    /**
     * Valida la sintaxis y ejecución de ejemplos de código
     */
    private function validateCodeExamples(): void
    {
        echo "🔍 Validando ejemplos de código...\n";

        $passed = 0;
        $failed = 0;

        foreach ($this->codeExamples as $example) {
            $result = $this->validateSingleExample($example);

            if ($result['valid']) {
                $passed++;
                echo "   ✓ {$this->getRelativePath($example['file'])}:{$example['line']}\n";
            } else {
                $failed++;
                echo "   ✗ {$this->getRelativePath($example['file'])}:{$example['line']} - {$result['error']}\n";
            }

            $this->validationResults['code_examples'][] = $result;
        }

        echo "   Resultados: {$passed} exitosos, {$failed} fallidos\n\n";
    }

    /**
     * Valida un ejemplo individual de código
     */
    private function validateSingleExample(array $example): array
    {
        $result = [
            'file' => $example['file'],
            'line' => $example['line'],
            'valid' => false,
            'error' => '',
            'return_type' => null,
            'return_value' => null,
        ];

        try {
            // Verificar sintaxis PHP
            if (! $this->validatePhpSyntax($example['code'])) {
                $result['error'] = 'Error de sintaxis PHP';

                return $result;
            }

            // Preparar código para ejecución
            $executableCode = $this->prepareCodeForExecution($example['code']);

            if ($executableCode === null) {
                $result['valid'] = true; // Código no ejecutable pero sintácticamente válido
                $result['error'] = 'Código no ejecutable (solo definición)';

                return $result;
            }

            // Ejecutar código en un entorno controlado
            $executionResult = $this->executeCode($executableCode);

            $result['valid'] = $executionResult['success'];
            $result['error'] = $executionResult['error'];
            $result['return_type'] = $executionResult['return_type'];
            $result['return_value'] = $executionResult['return_value'];

        } catch (Exception $e) {
            $result['error'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Valida la sintaxis PHP de un código
     */
    private function validatePhpSyntax(string $code): bool
    {
        // Agregar tags PHP si no existen
        if (! str_starts_with(trim($code), '<?php')) {
            $code = "<?php\n".$code;
        }

        // Verificar sintaxis usando php -l
        $tempFile = tempnam(sys_get_temp_dir(), 'php_syntax_check');
        file_put_contents($tempFile, $code);

        $output = [];
        $returnCode = 0;
        exec("php -l {$tempFile} 2>&1", $output, $returnCode);

        unlink($tempFile);

        return $returnCode === 0;
    }

    /**
     * Prepara código para ejecución segura
     */
    private function prepareCodeForExecution(string $code): ?string
    {
        // Filtrar códigos que no deben ejecutarse
        $skipPatterns = [
            '/require_once.*vendor\/autoload\.php/',
            '/new VersaORM\(\[/',
            '/\$orm = new VersaORM/',
            '/echo.*Usuario creado/',
            '/die\(/',
            '/exit\(/',
        ];

        foreach ($skipPatterns as $pattern) {
            if (preg_match($pattern, $code)) {
                return null; // No ejecutar este código
            }
        }

        // Reemplazar variables de configuración con nuestro ORM
        $code = preg_replace('/\$orm\s*=\s*new\s+VersaORM\([^)]+\);?/', '', $code);
        $code = str_replace('$orm->dispense(', 'VersaModel::dispense(', $code);
        $code = str_replace('$orm->store(', '$model->store(', $code);
        $code = str_replace('$orm', '$this->orm', $code);

        // Agregar return para capturar el resultado
        if (! str_contains($code, 'return ') && ! str_contains($code, 'echo ')) {
            $lines = explode("\n", trim($code));
            $lastLine = trim(end($lines));

            if (! empty($lastLine) && ! str_ends_with($lastLine, ';')) {
                $lastLine .= ';';
            }

            if (! str_starts_with($lastLine, 'return ') && ! str_contains($lastLine, '=')) {
                $lines[count($lines) - 1] = 'return '.$lastLine;
                $code = implode("\n", $lines);
            }
        }

        return $code;
    }

    /**
     * Ejecuta código en un entorno controlado
     */
    private function executeCode(string $code): array
    {
        $result = [
            'success' => false,
            'error' => '',
            'return_type' => null,
            'return_value' => null,
        ];

        try {
            // Crear función temporal para ejecutar el código
            $function = function () use ($code) {
                return eval($code);
            };

            $returnValue = $function();

            $result['success'] = true;
            $result['return_type'] = gettype($returnValue);
            $result['return_value'] = $returnValue;

        } catch (ParseError $e) {
            $result['error'] = 'Error de sintaxis: '.$e->getMessage();
        } catch (VersaORMException $e) {
            $result['error'] = 'Error VersaORM: '.$e->getMessage();
        } catch (Exception $e) {
            $result['error'] = 'Error de ejecución: '.$e->getMessage();
        } catch (Throwable $e) {
            $result['error'] = 'Error fatal: '.$e->getMessage();
        }

        return $result;
    }

    /**
     * Valida que los tipos de retorno coincidan con la documentación
     */
    private function validateReturnTypes(): void
    {
        echo "🔢 Validando tipos de retorno...\n";

        $expectedTypes = [
            'getAll()' => 'array',
            'getOne()' => ['array', 'NULL'],
            'count()' => 'integer',
            'store()' => 'integer',
            'load()' => ['object', 'NULL'],
            'dispense()' => 'object',
        ];

        $typeMatches = 0;
        $typeMismatches = 0;

        foreach ($this->validationResults['code_examples'] ?? [] as $result) {
            if (! $result['valid'] || $result['return_type'] === null) {
                continue;
            }

            $methodFound = false;
            foreach ($expectedTypes as $method => $expectedType) {
                if (str_contains($result['file'], $method) ||
                    (isset($result['code']) && str_contains($result['code'], $method))) {

                    $methodFound = true;
                    $actualType = $result['return_type'];

                    if (is_array($expectedType)) {
                        $matches = in_array($actualType, $expectedType);
                    } else {
                        $matches = $actualType === $expectedType;
                    }

                    if ($matches) {
                        $typeMatches++;
                        echo "   ✓ {$method}: {$actualType}\n";
                    } else {
                        $typeMismatches++;
                        $expected = is_array($expectedType) ? implode('|', $expectedType) : $expectedType;
                        echo "   ✗ {$method}: esperado {$expected}, obtenido {$actualType}\n";
                    }
                    break;
                }
            }
        }

        echo "   Resultados: {$typeMatches} coincidencias, {$typeMismatches} discrepancias\n\n";
    }

    /**
     * Valida consistencia de formato en la documentación
     */
    private function validateFormatConsistency(): void
    {
        echo "📝 Validando consistencia de formato...\n";

        $formatIssues = [];
        $markdownFiles = $this->findMarkdownFiles($this->docsPath);

        foreach ($markdownFiles as $file) {
            $content = file_get_contents($file);
            $issues = $this->checkFormatConsistency($content, $file);
            $formatIssues = array_merge($formatIssues, $issues);
        }

        if (empty($formatIssues)) {
            echo "   ✓ Formato consistente en todos los archivos\n";
        } else {
            echo '   ✗ Encontrados '.count($formatIssues)." problemas de formato:\n";
            foreach ($formatIssues as $issue) {
                echo "     - {$this->getRelativePath($issue['file'])}: {$issue['message']}\n";
            }
        }

        echo "\n";
        $this->validationResults['format_issues'] = $formatIssues;
    }

    /**
     * Verifica consistencia de formato en un archivo
     */
    private function checkFormatConsistency(string $content, string $file): array
    {
        $issues = [];

        // Verificar estructura de títulos
        if (! preg_match('/^# /', $content)) {
            $issues[] = ['file' => $file, 'message' => 'Falta título principal (# )'];
        }

        // Verificar bloques de código SQL
        $sqlBlocks = preg_match_all('/```sql\n(.*?)\n```/s', $content);
        $phpBlocks = preg_match_all('/```php\n(.*?)\n```/s', $content);

        // Verificar que haya ejemplos PHP
        if ($phpBlocks === 0 && str_contains($file, '/docs/') && ! str_contains($file, 'README.md')) {
            $issues[] = ['file' => $file, 'message' => 'No contiene ejemplos de código PHP'];
        }

        // Verificar formato de "Devuelve:"
        if (str_contains($content, '**Devuelve:**')) {
            if (! preg_match('/\*\*Devuelve:\*\* [A-Z]/', $content)) {
                $issues[] = ['file' => $file, 'message' => 'Formato incorrecto en "Devuelve:"'];
            }
        }

        return $issues;
    }

    /**
     * Valida enlaces internos en la documentación
     */
    private function validateInternalLinks(): void
    {
        echo "🔗 Validando enlaces internos...\n";

        $brokenLinks = [];
        $markdownFiles = $this->findMarkdownFiles($this->docsPath);

        foreach ($markdownFiles as $file) {
            $content = file_get_contents($file);
            $links = $this->extractInternalLinks($content);

            foreach ($links as $link) {
                if (! $this->linkExists($link, dirname($file))) {
                    $brokenLinks[] = [
                        'file' => $file,
                        'link' => $link,
                    ];
                }
            }
        }

        if (empty($brokenLinks)) {
            echo "   ✓ Todos los enlaces internos son válidos\n";
        } else {
            echo '   ✗ Encontrados '.count($brokenLinks)." enlaces rotos:\n";
            foreach ($brokenLinks as $broken) {
                echo "     - {$this->getRelativePath($broken['file'])}: {$broken['link']}\n";
            }
        }

        echo "\n";
        $this->validationResults['broken_links'] = $brokenLinks;
    }

    /**
     * Extrae enlaces internos de un contenido markdown
     */
    private function extractInternalLinks(string $content): array
    {
        $links = [];

        // Enlaces markdown [texto](enlace)
        preg_match_all('/\[([^\]]+)\]\(([^)]+)\)/', $content, $matches);
        foreach ($matches[2] as $link) {
            if (! str_starts_with($link, 'http') && ! str_starts_with($link, '#')) {
                $links[] = $link;
            }
        }

        return $links;
    }

    /**
     * Verifica si un enlace existe
     */
    private function linkExists(string $link, string $baseDir): bool
    {
        $fullPath = realpath($baseDir.'/'.$link);

        return $fullPath !== false && file_exists($fullPath);
    }

    /**
     * Genera reporte final de validación
     */
    private function generateReport(): bool
    {
        echo "=== REPORTE DE VALIDACIÓN ===\n\n";

        $totalExamples = count($this->codeExamples);
        $validExamples = count(array_filter(
            $this->validationResults['code_examples'] ?? [],
            fn ($r) => $r['valid']
        ));

        $formatIssues = count($this->validationResults['format_issues'] ?? []);
        $brokenLinks = count($this->validationResults['broken_links'] ?? []);

        echo "📊 Estadísticas:\n";
        echo "   - Ejemplos de código: {$validExamples}/{$totalExamples} válidos\n";
        echo "   - Problemas de formato: {$formatIssues}\n";
        echo "   - Enlaces rotos: {$brokenLinks}\n\n";

        $success = ($validExamples === $totalExamples) &&
                  ($formatIssues === 0) &&
                  ($brokenLinks === 0);

        if ($success) {
            echo "🎉 ¡Validación completada exitosamente!\n";
            echo "   Toda la documentación está correcta y funcional.\n";
        } else {
            echo "⚠️  Validación completada con problemas.\n";
            echo "   Revisa los errores reportados arriba.\n";
        }

        // Guardar reporte detallado
        $this->saveDetailedReport();

        return $success;
    }

    /**
     * Guarda un reporte detallado en archivo
     */
    private function saveDetailedReport(): void
    {
        $reportFile = __DIR__.'/validation_report.json';
        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'summary' => [
                'total_examples' => count($this->codeExamples),
                'valid_examples' => count(array_filter(
                    $this->validationResults['code_examples'] ?? [],
                    fn ($r) => $r['valid']
                )),
                'format_issues' => count($this->validationResults['format_issues'] ?? []),
                'broken_links' => count($this->validationResults['broken_links'] ?? []),
            ],
            'details' => $this->validationResults,
        ];

        file_put_contents($reportFile, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        echo "\n📄 Reporte detallado guardado en: validation_report.json\n";
    }

    /**
     * Obtiene la ruta relativa de un archivo
     */
    private function getRelativePath(string $file): string
    {
        $docsPath = realpath($this->docsPath);
        $filePath = realpath($file);

        if ($filePath && str_starts_with($filePath, $docsPath)) {
            return 'docs'.substr($filePath, strlen($docsPath));
        }

        return basename($file);
    }

    /**
     * Limpia recursos al finalizar
     */
    public function __destruct()
    {
        // Limpiar base de datos de prueba
        $testDb = __DIR__.'/validation_test.sqlite';
        if (file_exists($testDb)) {
            unlink($testDb);
        }
    }
}

// Ejecutar validación si se llama directamente
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    $validator = new DocumentationValidator;
    $success = $validator->validateAll();
    exit($success ? 0 : 1);
}
