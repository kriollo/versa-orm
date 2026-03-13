<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use SebastianBergmann\CodeCoverage\CodeCoverage;
use SebastianBergmann\CodeCoverage\Report\Html\Facade as HtmlReport;
use SebastianBergmann\CodeCoverage\Report\Text as TextReport;
use SebastianBergmann\CodeCoverage\Report\Clover as CloverReport;
use SebastianBergmann\CodeCoverage\Report\Thresholds;

$partsDir = __DIR__ . '/../build/coverage/parts';
$outputDir = __DIR__ . '/../build/coverage/combined';

if (!is_dir($outputDir)) {
    mkdir($outputDir, 0777, true);
}

if (!is_dir($partsDir)) {
    echo "No parts directory found at $partsDir\n";
    exit(1);
}

$files = glob("$partsDir/*.cov");
if (empty($files)) {
    echo "No .cov files found in $partsDir\n";
    exit(1);
}

echo "Found " . count($files) . " coverage parts. Merging...\n";

// We need a base coverage object. We'll load the first one and then merge others.
$mergedCoverage = null;

foreach ($files as $file) {
    echo "Processing $file...\n";
    $coverage = include $file;

    if (!$coverage instanceof CodeCoverage) {
        echo "Warning: $file did not return a valid CodeCoverage object.\n";
        continue;
    }

    if ($mergedCoverage === null) {
        $mergedCoverage = $coverage;
    } else {
        $mergedCoverage->merge($coverage);
    }
}

if ($mergedCoverage === null) {
    echo "Failed to produce a merged coverage object.\n";
    exit(1);
}

echo "Generating reports...\n";

(new HtmlReport())->process($mergedCoverage, $outputDir . '/html');
(new TextReport(Thresholds::default()))->process($mergedCoverage, false); // Returns string
$text = (new TextReport(Thresholds::default()))->process($mergedCoverage, false);
file_put_contents($outputDir . '/coverage.txt', $text);
(new CloverReport())->process($mergedCoverage, $outputDir . '/clover.xml');

echo "\nDone! Combined report generated in:\n";
echo "HTML: " . realpath($outputDir . '/html/index.html') . "\n";
echo "Text: " . realpath($outputDir . '/coverage.txt') . "\n";
