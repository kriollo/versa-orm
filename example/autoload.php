<?php
// Autoload simple para src/ y example/models
spl_autoload_register(function ($class) {
    $prefixes = [
        'VersaORM\\' => __DIR__ . '/../src/',
        'Example\\Models\\' => __DIR__ . '/models/'
    ];
    foreach ($prefixes as $prefix => $base_dir) {
        if (strpos($class, $prefix) === 0) {
            $relative_class = substr($class, strlen($prefix));
            $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
            if (file_exists($file)) {
                require_once $file;
                return;
            }
        }
    }
});
