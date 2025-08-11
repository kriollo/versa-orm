<?php

declare(strict_types=1);

/**
 * Autoloader para la aplicación demo.
 */

// Cargar Composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';

// Autoload temprano para App\ (Request, OrmFactory, App, ModelManager) y App\Models\
spl_autoload_register(function ($class): void {
    if (strpos($class, 'App\\Models\\') === 0) {
        $className = str_replace('App\\Models\\', '', $class);
        $file      = __DIR__ . '/models/' . $className . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
    }
    if (strpos($class, 'App\\') === 0) {
        $relative = str_replace('App\\', '', $class);
        $relative = str_replace('\\', '/', $relative);
        $file = __DIR__ . '/app/' . $relative . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
    }
});


// Cargar configuración
$config = require_once __DIR__ . '/config.php';

// Configurar zona horaria
date_default_timezone_set($config['app']['timezone'] ?? 'UTC');
// Inicializar VersaORM por petición
use App\Request;
use App\OrmFactory;
use App\App;

// Construir una Request y un ORM por cada ejecución (request-scoped)
$request = Request::fromGlobals();
// Construir contenedor con inicialización perezosa del ORM
$app = new App($request, $config);

// Autoloader ya registrado arriba

// Función helper para renderizar vistas
function render($view, $data = []): void
{
    global $config;
    extract($data);
    $viewFile = __DIR__ . '/views/' . $view . '.php';

    if (!file_exists($viewFile)) {
        die("Vista no encontrada: {$view}");
    }

    ob_start();
    include $viewFile;
    $content = ob_get_clean();

    // Si no es una vista parcial, usar layout
    if (!isset($noLayout) || !$noLayout) {
        include __DIR__ . '/views/layout.php';
    } else {
        echo $content;
    }
}

// Función helper para redireccionar
function redirect($url): void
{
    header("Location: {$url}");
    exit;
}

// Función helper para mostrar mensajes flash
function flash($type, $message): void
{
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

function getFlash()
{
    if (isset($_SESSION['flash'])) {
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);
        return $flash;
    }
    return null;
}

// Exponer request actual para el ejemplo
function request(): \App\Request
{
    global $request;
    return $request;
}

function app(): \App\App
{
    global $app;
    return $app;
}

function models(): \App\ModelManager
{
    return app()->models();
}

// Iniciar sesión
session_start();

/**
 * Helper para convertir fechas a timestamp de manera segura.
 * Maneja tanto strings como objetos DateTime.
 */
function safe_strtotime($date)
{
    if ($date instanceof DateTime) {
        return $date->getTimestamp();
    }
    return strtotime($date);
}

/**
 * Helper para formatear fechas de manera segura.
 * Maneja tanto strings como objetos DateTime.
 */
function safe_date($format, $date)
{
    if ($date instanceof DateTime) {
        return $date->format($format);
    }
    return date($format, strtotime($date));
}

/**
 * Helper para formatear fechas de manera segura con manejo de errores.
 * Maneja tanto strings como objetos DateTime.
 */
function safe_date_format($date, $format = 'Y-m-d H:i:s')
{
    if (empty($date)) {
        return '-';
    }

    if ($date instanceof DateTime) {
        return $date->format($format);
    }

    if (is_string($date)) {
        $timestamp = strtotime($date);
        if ($timestamp === false) {
            return $date; // Devolver el valor original si no se puede parsear
        }
        return date($format, $timestamp);
    }

    return (string) $date;
}
