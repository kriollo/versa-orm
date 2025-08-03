<?php

/**
 * Autoloader para la aplicación demo
 */

// Cargar Composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';

// Configurar zona horaria
date_default_timezone_set('America/Mexico_City');

// Cargar configuración
$config = require_once __DIR__ . '/config.php';

// Inicializar VersaORM
use VersaORM\VersaORM;
use VersaORM\VersaModel;

try {
    $orm = new VersaORM($config['versaorm'] + $config['database']);
    VersaModel::setORM($orm);
} catch (Exception $e) {
    die("Error al inicializar VersaORM: " . $e->getMessage());
}

// Autoloader para modelos
spl_autoload_register(function ($class) {
    if (strpos($class, 'App\\Models\\') === 0) {
        $className = str_replace('App\\Models\\', '', $class);
        $file = __DIR__ . '/models/' . $className . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
    }
});

// Función helper para renderizar vistas
function render($view, $data = [])
{
    global $config;
    extract($data);
    $viewFile = __DIR__ . '/views/' . $view . '.php';

    if (!file_exists($viewFile)) {
        die("Vista no encontrada: $view");
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
function redirect($url)
{
    header("Location: $url");
    exit;
}

// Función helper para mostrar mensajes flash
function flash($type, $message)
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

// Iniciar sesión
session_start();
