<?php
// Parse a PHPUnit clover.xml and list files in src/ with coverage below threshold
if ($argc < 2) {
    fwrite(STDERR, "Usage: php parse-clover.php build/logs/clover.xml [threshold]\n");
    exit(2);
}
$file = $argv[1];
$threshold = isset($argv[2]) ? (int)$argv[2] : 70;
if (!file_exists($file)) {
    fwrite(STDERR, "Clover file not found: $file\n");
    exit(2);
}
$xml = @simplexml_load_file($file);
if (!$xml) {
    fwrite(STDERR, "Failed to parse clover XML: $file\n");
    exit(2);
}

echo "Coverage threshold: $threshold%\n";
echo "Files in src/ under threshold:\n\n";

$low = [];
foreach ($xml->project->file as $fileNode) {
    $path = (string)$fileNode['name'];
    if (strpos($path, DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR) === false) continue;
    $metrics = $fileNode->metrics;
    $statements = (int)$metrics['statements'];
    $covered = (int)$metrics['coveredstatements'];
    $percent = $statements > 0 ? ($covered / $statements) * 100 : 100;
    if ($percent < $threshold) {
        $low[] = [
            'file' => $path,
            'statements' => $statements,
            'covered' => $covered,
            'percent' => round($percent, 1),
        ];
    }
}

usort($low, function ($a, $b) {
    return $a['percent'] <=> $b['percent'];
});

foreach ($low as $row) {
    echo sprintf("%5.1f%%  %5d/%5d  %s\n", $row['percent'], $row['covered'], $row['statements'], $row['file']);
}

if (empty($low)) {
    echo "All src/ files meet the threshold.\n";
}

exit(0);
