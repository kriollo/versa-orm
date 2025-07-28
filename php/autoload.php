<?php

/**
 * VersaORM-PHP Autoloader
 * 
 * Este archivo carga automáticamente todas las dependencias necesarias.
 * Simplemente incluye este archivo y tendrás acceso a toda la funcionalidad.
 * 
 * Uso:
 *   require_once 'php/autoload.php';
 *   
 *   // Ahora puedes usar VersaORM directamente
 *   VersaORM::connect([...]);
 * 
 * @version 1.0.0
 * @author VersaORM Team
 */

declare(strict_types=1);

// Verificar versión de PHP
if (version_compare(PHP_VERSION, '7.4.0', '<')) {
    throw new Exception('VersaORM requiere PHP 7.4 o superior. Versión actual: ' . PHP_VERSION);
}

// Definir directorio base
if (!defined('VERSAORM_BASE_PATH')) {
    define('VERSAORM_BASE_PATH', __DIR__);
}

// Cargar todas las clases necesarias en el orden correcto
$requiredFiles = [
    'VersaORM.php',
    'VersaORMQueryBuilder.php', 
    'VersaORMModel.php'
];

foreach ($requiredFiles as $file) {
    $filePath = VERSAORM_BASE_PATH . DIRECTORY_SEPARATOR . $file;
    
    if (!file_exists($filePath)) {
        throw new Exception("Error: No se encontró el archivo requerido: {$file}");
    }
    
    require_once $filePath;
}

// Verificar que las clases se cargaron correctamente
$requiredClasses = ['VersaORM', 'VersaORMQueryBuilder', 'VersaORMModel'];

foreach ($requiredClasses as $className) {
    if (!class_exists($className)) {
        throw new Exception("Error: No se pudo cargar la clase {$className}");
    }
}

// Definir que VersaORM está cargado
if (!defined('VERSAORM_LOADED')) {
    define('VERSAORM_LOADED', true);
    define('VERSAORM_VERSION', '1.0.0');
}

// Mensaje de debug opcional (solo si está habilitado)
if (defined('VERSAORM_DEBUG') && VERSAORM_DEBUG) {
    echo "✅ VersaORM-PHP v" . VERSAORM_VERSION . " cargado exitosamente\n";
    echo "📚 Clases disponibles: " . implode(', ', $requiredClasses) . "\n";
}
