<?php
// Usage: php coverage-stats.php path/to/clover.xml
if ($argc < 2) {
    fwrite(STDERR, "Usage: php coverage-stats.php path/to/clover.xml\n");
    exit(2);
}
$file = $argv[1];
if (!file_exists($file)) {
    fwrite(STDERR, "Clover file not found: $file\n");
    exit(2);
}
$xml = @simplexml_load_file($file);
if (!$xml) {
    fwrite(STDERR, "Failed to parse clover XML: $file\n");
    exit(2);
}

$totalStatements = 0;
$totalCovered = 0;
$srcStatements = 0;
$srcCovered = 0;
$files = [];

foreach ($xml->project->file as $fileNode) {
    $path = (string)$fileNode['name'];
    $metrics = $fileNode->metrics;
    $statements = isset($metrics['statements']) ? (int)$metrics['statements'] : 0;
    $covered = isset($metrics['coveredstatements']) ? (int)$metrics['coveredstatements'] : 0;

    $totalStatements += $statements;
    $totalCovered += $covered;

    if (strpos($path, '/src/') !== false || strpos($path, '\\src\\') !== false) {
        $srcStatements += $statements;
        $srcCovered += $covered;
    }

    $percent = $statements > 0 ? ($covered / $statements) * 100 : 100;
    $files[] = ['path' => $path, 'statements' => $statements, 'covered' => $covered, 'percent' => $percent];
}

usort($files, function ($a, $b) {
    return $a['percent'] <=> $b['percent'];
});

echo "Overall coverage:\n";
if ($totalStatements > 0) {
    $overall = ($totalCovered / $totalStatements) * 100;
    echo sprintf("  Covered %d/%d (%.2f%%)\n", $totalCovered, $totalStatements, $overall);
} else {
    echo "  No statements found in clover.xml\n";
}

echo "\nCoverage for src/:\n";
if ($srcStatements > 0) {
    $srcPercent = ($srcCovered / $srcStatements) * 100;
    echo sprintf("  Covered %d/%d (%.2f%%)\n", $srcCovered, $srcStatements, $srcPercent);
} else {
    echo "  No src/ files found in clover.xml\n";
}

echo "\n10 worst-covered src/ files:\n";
$count = 0;
foreach ($files as $f) {
    if ($count >= 10) break;
    if (strpos($f['path'], '/src/') === false && strpos($f['path'], '\\src\\') === false) continue;
    printf("%5.1f%%  %5d/%5d  %s\n", $f['percent'], $f['covered'], $f['statements'], $f['path']);
    $count++;
}

if ($count === 0) {
    echo "  (no src/ files to show)\n";
}

exit(0);
