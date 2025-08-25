<?php
// Consolidate PHPUnit JUnit reports produced by the PHP compatibility matrix
$results = [];
$versions = ['8.1', '8.2', '8.3'];

foreach ($versions as $version) {
    $artifactDir = "artifacts/php-compatibility-results-$version/tests/reports/php-compatibility";
    if (is_dir($artifactDir)) {
        $junitFile = $artifactDir . "/junit-php$version.xml";
        if (file_exists($junitFile)) {
            $xml = @simplexml_load_file($junitFile);
            if ($xml) {
                $results[$version] = [
                    'tests' => (int)$xml['tests'],
                    'failures' => (int)$xml['failures'],
                    'errors' => (int)$xml['errors'],
                    'time' => (float)$xml['time'],
                    'success_rate' => ((int)$xml['tests']) > 0 ? (((int)$xml['tests'] - (int)$xml['failures'] - (int)$xml['errors']) / (int)$xml['tests']) * 100 : 0
                ];
            }
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

file_put_contents('consolidated-reports/matrix-summary.json', json_encode([
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

if ($totalFailures > 0 || $totalErrors > 0) {
    echo "\n❌ Some tests failed across PHP versions\n";
    exit(1);
} else {
    echo "\n✅ All tests passed across all PHP versions\n";
}
