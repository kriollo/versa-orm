<?php

$xml = simplexml_load_file(__DIR__ . '/../build/logs/clover.xml');
$total = 0;
$covered = 0;
foreach ($xml->project->file as $file) {
    $name = (string)$file['name'];
    if (strpos($name, DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR) !== false) {
        foreach ($file->metrics as $m) {
            $attrs = $m->attributes();
            $s = (int)$attrs['statements'];
            $c = (int)$attrs['coveredstatements'];
            $total += $s;
            $covered += $c;
        }
    }
}
echo "total_statements={$total}\n";
echo "covered_statements={$covered}\n";
echo sprintf("coverage=%.2f\n", ($total > 0 ? ($covered / $total * 100) : 0));
