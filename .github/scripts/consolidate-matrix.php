<?php
// Consolidate PHPUnit JUnit reports produced by the PHP compatibility matrix

$root = __DIR__ . '/../../';
$artifactsBase = $root . 'artifacts/';

// Find junit files recursively under artifacts/
$results = [];

if (!is_dir($artifactsBase)) {
    fwrite(STDERR, "No artifacts directory found at: $artifactsBase\n");
    exit(1);
}

$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($artifactsBase));
foreach ($rii as $file) {
    if ($file->isDir()) continue;
    $filename = $file->getFilename();
    if (preg_match('/^junit-php(\d+(?:\.\d+)*).*\.xml$/', $filename, $m)) {
        $version = $m[1];
        $path = $file->getPathname();
        $xml = @simplexml_load_file($path);
        if ($xml) {
            $tests = (int)$xml['tests'];
            $failures = (int)$xml['failures'];
            $errors = (int)$xml['errors'];
            $time = (float)$xml['time'];
            
            if (!isset($results[$version])) {
                $results[$version] = [
                    'tests' => 0,
                    'failures' => 0,
                    'errors' => 0,
                    'time' => 0,
                    'success_rate' => 0,
                    'paths' => [],
                ];
            }
            
            $results[$version]['tests'] += $tests;
            $results[$version]['failures'] += $failures;
            $results[$version]['errors'] += $errors;
            $results[$version]['time'] += $time;
            $results[$version]['paths'][] = $path;
            
            // Recalculate success rate for the version
            $vTests = $results[$version]['tests'];
            $vFails = $results[$version]['failures'];
            $vErrs = $results[$version]['errors'];
            $results[$version]['success_rate'] = $vTests > 0 ? (($vTests - $vFails - $vErrs) / $vTests) * 100 : 0;
            
        } else {
            // parse error reading xml
            fwrite(STDERR, "Failed to parse XML at: $path\n");
        }
    }
}

echo "=== PHP Compatibility Matrix Results ===\n";
echo "| PHP Version | Tests | Failures | Errors | Success Rate | Time |\n";
echo "|-------------|-------|----------|--------|--------------|------|\n";

$totalTests = 0;
$totalFailures = 0;
$totalErrors = 0;
$totalTime = 0.0;

ksort($results, SORT_NATURAL);
foreach ($results as $version => $data) {
    $successRate = number_format($data['success_rate'], 1);
    $time = number_format($data['time'], 2);
    echo "| PHP $version | {$data['tests']} | {$data['failures']} | {$data['errors']} | {$successRate}% | {$time}s |\n";
    $totalTests += $data['tests'];
    $totalFailures += $data['failures'];
    $totalErrors += $data['errors'];
    $totalTime += $data['time'];
}

$overallSuccessRate = $totalTests > 0 ? (($totalTests - $totalFailures - $totalErrors) / $totalTests) * 100 : 0;
$overallTime = number_format($totalTime, 2);
echo "|-------------|-------|----------|--------|--------------|------|\n";
echo "| **TOTAL** | $totalTests | $totalFailures | $totalErrors | " . number_format($overallSuccessRate, 1) . "% | {$overallTime}s |\n";

if (!is_dir($root . 'consolidated-reports')) {
    @mkdir($root . 'consolidated-reports', 0777, true);
}

file_put_contents($root . 'consolidated-reports/matrix-summary.json', json_encode([
    'timestamp' => date('c'),
    'versions' => $results,
    'summary' => [
        'total_tests' => $totalTests,
        'total_failures' => $totalFailures,
        'total_errors' => $totalErrors,
        'overall_success_rate' => $overallSuccessRate,
        'total_time' => $totalTime,
    ]
], JSON_PRETTY_PRINT));

if (count($results) === 0) {
    echo "\n⚠️ No JUnit report files were found in artifacts/.\n";
    exit(1);
}

if ($totalFailures > 0 || $totalErrors > 0) {
    echo "\n❌ Some tests failed across PHP versions\n";
    exit(1);
} else {
    echo "\n✅ All tests passed across all PHP versions\n";
    exit(0);
}
