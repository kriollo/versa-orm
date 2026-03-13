<?php
// Simple validator for PHPUnit JUnit XML used in CI validation step
if ($argc < 2) {
    fwrite(STDERR, "Usage: php validate-junit.php <junit-xml>\n");
    exit(2);
}
$file = $argv[1];
if (!file_exists($file)) {
    fwrite(STDERR, "JUnit file not found: $file\n");
    exit(2);
}
$xml = @simplexml_load_file($file);
if (!$xml) {
    fwrite(STDERR, "Failed to parse JUnit XML: $file\n");
    exit(2);
}
$tests = (int)$xml['tests'];
$failures = (int)$xml['failures'];
$errors = (int)$xml['errors'];
echo "JUnit: tests={$tests}, failures={$failures}, errors={$errors}\n";
if ($failures > 0 || $errors > 0) {
    fwrite(STDOUT, "❌ Some tests failed in JUnit report\n");
    exit(1);
}
fwrite(STDOUT, "✅ JUnit OK\n");
exit(0);
