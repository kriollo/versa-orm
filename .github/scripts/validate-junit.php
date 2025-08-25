<?php
// Validar un archivo JUnit XML generado por PHPUnit.
// Uso: php validate-junit.php path/to/junit.xml

if ($argc < 2) {
    fwrite(STDERR, "Usage: php validate-junit.php path/to/junit.xml\n");
    exit(2);
}

$file = $argv[1];
if (!file_exists($file)) {
    fwrite(STDERR, "JUnit file not found: $file\n");
    exit(1);
}

$xml = @simplexml_load_file($file);
if (!$xml) {
    fwrite(STDERR, "Failed to parse JUnit XML: $file\n");
    exit(1);
}

$tests = (int)$xml['tests'];
$failures = (int)$xml['failures'];
$errors = (int)$xml['errors'];

echo "Tests: $tests, Failures: $failures, Errors: $errors\n";

if ($failures > 0 || $errors > 0) {
    exit(1);
}

exit(0);
