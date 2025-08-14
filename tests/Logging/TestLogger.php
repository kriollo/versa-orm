<?php

declare(strict_types=1);

namespace VersaORM\Tests\Logging;

use DateTime;

use function array_slice;
use function count;
use function in_array;

/**
 * Sistema de logging para el framework de testing.
 *
 * Proporciona logging estructurado con diferentes niveles de severidad,
 * rotación de archivos y formateo consistente para el sistema de QA.
 */
class TestLogger
{
    private const LEVELS = [
        'debug' => 0,
        'info' => 1,
        'warning' => 2,
        'error' => 3,
        'critical' => 4,
    ];

    private string $logLevel;

    private string $outputDir;

    private int $maxFiles;

    private string $currentLogFile;

    public function __construct(array $config = [])
    {
        $this->logLevel = $config['level'] ?? 'info';
        $this->outputDir = $config['output_dir'] ?? 'tests/logs';
        $this->maxFiles = $config['max_files'] ?? 10;

        $this->ensureLogDirectory();
        $this->currentLogFile = $this->getCurrentLogFile();
        $this->rotateLogsIfNeeded();
    }

    /**
     * Log de nivel debug.
     */
    public function debug(string $message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }

    /**
     * Log de nivel info.
     */
    public function info(string $message, array $context = []): void
    {
        $this->log('info', $message, $context);
    }

    /**
     * Log de nivel warning.
     */
    public function warning(string $message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    /**
     * Log de nivel error.
     */
    public function error(string $message, array $context = []): void
    {
        $this->log('error', $message, $context);
    }

    /**
     * Log de nivel critical.
     */
    public function critical(string $message, array $context = []): void
    {
        $this->log('critical', $message, $context);
    }

    /**
     * Obtiene estadísticas de logging.
     */
    public function getStats(): array
    {
        $logFiles = glob($this->outputDir . '/test-qa-*.log');
        $totalSize = 0;
        $totalLines = 0;

        foreach ($logFiles as $file) {
            $totalSize += filesize($file);
            $totalLines += count(file($file, FILE_IGNORE_NEW_LINES));
        }

        return [
            'total_files' => count($logFiles),
            'total_size_bytes' => $totalSize,
            'total_size_formatted' => $this->formatBytes($totalSize),
            'total_lines' => $totalLines,
            'current_log_file' => $this->currentLogFile,
            'log_level' => $this->logLevel,
        ];
    }

    /**
     * Limpia todos los archivos de log.
     */
    public function clearLogs(): void
    {
        $logFiles = glob($this->outputDir . '/test-qa-*.log');

        foreach ($logFiles as $file) {
            unlink($file);
        }

        $this->info('All log files cleared');
    }

    /**
     * Obtiene las últimas N líneas del log actual.
     */
    public function getTailLines(int $lines = 50): array
    {
        if (!file_exists($this->currentLogFile)) {
            return [];
        }

        $fileLines = file($this->currentLogFile, FILE_IGNORE_NEW_LINES);

        return array_slice($fileLines, -$lines);
    }

    /**
     * Busca en los logs por patrón.
     */
    public function searchLogs(string $pattern, int $maxResults = 100): array
    {
        $results = [];
        $logFiles = glob($this->outputDir . '/test-qa-*.log');

        foreach ($logFiles as $file) {
            $lines = file($file, FILE_IGNORE_NEW_LINES);

            foreach ($lines as $lineNumber => $line) {
                if (stripos($line, $pattern) !== false) {
                    $results[] = [
                        'file' => basename($file),
                        'line_number' => $lineNumber + 1,
                        'content' => $line,
                    ];

                    if (count($results) >= $maxResults) {
                        break 2;
                    }
                }
            }
        }

        return $results;
    }

    /**
     * Método principal de logging.
     */
    private function log(string $level, string $message, array $context = []): void
    {
        if (!$this->shouldLog($level)) {
            return;
        }

        $logEntry = $this->formatLogEntry($level, $message, $context);
        $this->writeToFile($logEntry);

        // También escribir a stdout para logs críticos y errores
        if (in_array($level, ['error', 'critical'], true)) {
            echo $logEntry . PHP_EOL;
        }
    }

    /**
     * Determina si se debe loggear el mensaje basado en el nivel.
     */
    private function shouldLog(string $level): bool
    {
        $currentLevelValue = self::LEVELS[$this->logLevel] ?? 1;
        $messageLevelValue = self::LEVELS[$level] ?? 0;

        return $messageLevelValue >= $currentLevelValue;
    }

    /**
     * Formatea una entrada de log.
     */
    private function formatLogEntry(string $level, string $message, array $context): string
    {
        $timestamp = (new DateTime())->format('Y-m-d H:i:s.u');
        $levelUpper = strtoupper($level);
        $pid = getmypid();

        $logEntry = "[{$timestamp}] [{$levelUpper}] [PID:{$pid}] {$message}";

        if ($context !== []) {
            $contextJson = json_encode($context, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $logEntry .= " Context: {$contextJson}";
        }

        return $logEntry;
    }

    /**
     * Escribe la entrada al archivo de log.
     */
    private function writeToFile(string $logEntry): void
    {
        file_put_contents($this->currentLogFile, $logEntry . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /**
     * Asegura que el directorio de logs existe.
     */
    private function ensureLogDirectory(): void
    {
        if (!is_dir($this->outputDir)) {
            mkdir($this->outputDir, 0755, true);
        }
    }

    /**
     * Obtiene el archivo de log actual.
     */
    private function getCurrentLogFile(): string
    {
        $date = date('Y-m-d');

        return $this->outputDir . "/test-qa-{$date}.log";
    }

    /**
     * Rota los archivos de log si es necesario.
     */
    private function rotateLogsIfNeeded(): void
    {
        $logFiles = glob($this->outputDir . '/test-qa-*.log');

        if (count($logFiles) <= $this->maxFiles) {
            return;
        }

        // Ordenar por fecha de modificación (más antiguos primero)
        usort($logFiles, static fn ($a, $b): int => filemtime($a) - filemtime($b));

        // Eliminar archivos más antiguos
        $filesToDelete = array_slice($logFiles, 0, count($logFiles) - $this->maxFiles);

        foreach ($filesToDelete as $file) {
            unlink($file);
        }
    }

    /**
     * Formatea bytes en unidades legibles.
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];

        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; ++$i) {
            $bytes /= 1024;
        }

        return round($bytes, 2) . ' ' . $units[$i];
    }
}
