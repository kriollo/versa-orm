<?php

declare(strict_types=1);

/**
 * Instalador de la demo.
 *
 * Funciona por web (abrir `install.php` en el navegador) y por CLI:
 *
 *     php install.php              # instala si hace falta y siembra datos
 *     php install.php --force      # recrea la base aunque ya exista (destructivo)
 *     php install.php --status     # sólo muestra el diagnóstico
 *     php install.php --no-seed    # instala el esquema sin datos de demostración
 */

use App\Installer;

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/app/Installer.php';

$config = require __DIR__ . '/app/config.php';
$installer = Installer::fromConfig($config);
$isCli = PHP_SAPI === 'cli';

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
if ($isCli) {
    $args = array_slice($argv, 1);
    $force = in_array('--force', $args, true);
    $statusOnly = in_array('--status', $args, true);
    $noSeed = in_array('--no-seed', $args, true);
    $status = $installer->status();

    echo "VersaORM Trello Demo — instalador\n\n";
    printf("  Servidor   %s:%d (%s)\n", $status['host'], $status['port'], $status['username']);
    printf("  Base       %s\n", $status['database']);
    printf("  Migración  %s\n", $status['migration_readable'] ? $status['migration'] : $status['migration'] . ' (NO legible)');

    if (!$status['server_reachable']) {
        printf("\n  ✗ No se puede conectar al servidor MySQL:\n    %s\n\n", (string) $status['server_error']);
        echo "  Revisa host, puerto y credenciales en example/app/config.php\n";
        exit(1);
    }
    printf("  Estado     %s\n", $status['installed'] ? 'instalada' : 'NO instalada');

    if ($status['missing_tables'] !== []) {
        printf("  Faltan     %s\n", implode(', ', $status['missing_tables']));
    }
    printf("  Datos      %s\n\n", $status['has_data'] ? 'sí' : 'no');

    if ($statusOnly) {
        exit($status['installed'] ? 0 : 1);
    }

    try {
        if (!$status['installed'] || $force) {
            if ($status['installed'] && $force) {
                echo "  ⚠ --force: se recrea la base y se pierden los datos actuales.\n";
            }

            foreach ($installer->runMigration($force) as $step) {
                echo "  ✓ {$step}\n";
            }
        } else {
            echo "  · La base ya está instalada, no se toca el esquema.\n";
        }

        if (!$noSeed && !$installer->hasData()) {
            foreach ($installer->seedDemoData() as $step) {
                echo "  ✓ Datos: {$step}\n";
            }
        } elseif (!$noSeed) {
            echo "  · Ya hay datos, no se siembra de nuevo.\n";
        }
    } catch (Throwable $e) {
        printf("\n  ✗ %s\n\n", $e->getMessage());
        exit(1);
    }

    echo "\n  Listo. Levanta la demo con:\n";
    echo "      php -S localhost:8000 -t example\n\n";
    exit(0);
}

// ---------------------------------------------------------------------------
// Web
// ---------------------------------------------------------------------------
$done = [];
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $force = isset($_POST['force']);
    $seed = isset($_POST['seed']);

    try {
        if (!$installer->isInstalled() || $force) {
            $done = $installer->runMigration($force);
        }

        if ($seed && !$installer->hasData()) {
            foreach ($installer->seedDemoData() as $step) {
                $done[] = 'Datos: ' . $step;
            }
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$status = $installer->status();
?>
<!DOCTYPE html>
<html lang="es" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instalar — VersaORM Trello Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="h-full bg-gray-100 text-gray-900">
<div class="max-w-2xl mx-auto px-4 py-10">
    <h1 class="text-2xl font-bold mb-1">VersaORM Trello Demo</h1>
    <p class="text-gray-600 mb-6">Instalación de la base de datos</p>

    <?php if ($error !== null): ?>
        <div class="mb-6 rounded-md border border-red-200 bg-red-50 p-4 text-red-800">
            <p class="font-semibold">No se pudo completar</p>
            <p class="text-sm mt-1"><?php echo htmlspecialchars($error); ?></p>
        </div>
    <?php endif; ?>

    <?php if ($done !== []): ?>
        <div class="mb-6 rounded-md border border-green-200 bg-green-50 p-4 text-green-800">
            <p class="font-semibold">Instalación completada</p>
            <ul class="text-sm mt-2 list-disc list-inside">
                <?php foreach ($done as $step): ?>
                    <li><?php echo htmlspecialchars($step); ?></li>
                <?php endforeach; ?>
            </ul>
            <a href="index.php?action=dashboard"
               class="inline-block mt-3 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700">
                Ir a la demo
            </a>
        </div>
    <?php endif; ?>

    <div class="rounded-md border border-gray-200 bg-white p-5 mb-6">
        <h2 class="font-semibold mb-3">Diagnóstico</h2>
        <dl class="text-sm space-y-1">
            <div class="flex justify-between"><dt class="text-gray-600">Servidor</dt>
                <dd><?php echo htmlspecialchars($status['host'] . ':' . $status['port']); ?>
                    <?php echo $status['server_reachable'] ? '✓' : '✗ sin conexión'; ?></dd></div>
            <div class="flex justify-between"><dt class="text-gray-600">Usuario</dt>
                <dd><?php echo htmlspecialchars($status['username']); ?></dd></div>
            <div class="flex justify-between"><dt class="text-gray-600">Base de datos</dt>
                <dd><?php echo htmlspecialchars($status['database']); ?>
                    <?php echo $status['database_exists'] ? '✓ existe' : '✗ no existe'; ?></dd></div>
            <div class="flex justify-between"><dt class="text-gray-600">Migración</dt>
                <dd><?php echo $status['migration_readable'] ? '✓ todoapp.sql' : '✗ no legible'; ?></dd></div>
            <div class="flex justify-between"><dt class="text-gray-600">Tablas</dt>
                <dd><?php echo $status['missing_tables'] === []
                        ? '✓ completas'
                        : '✗ faltan: ' . htmlspecialchars(implode(', ', $status['missing_tables'])); ?></dd></div>
            <div class="flex justify-between"><dt class="text-gray-600">Datos de demostración</dt>
                <dd><?php echo $status['has_data'] ? '✓ cargados' : '· sin cargar'; ?></dd></div>
        </dl>
    </div>

    <?php if (!$status['server_reachable']): ?>
        <div class="rounded-md border border-amber-200 bg-amber-50 p-4 text-amber-900 text-sm">
            <p class="font-semibold mb-1">Sin conexión al servidor MySQL</p>
            <p><?php echo htmlspecialchars((string) $status['server_error']); ?></p>
            <p class="mt-2">Ajusta host, puerto y credenciales en <code>example/app/config.php</code>.</p>
        </div>
    <?php elseif ($status['installed'] && $status['has_data']): ?>
        <div class="rounded-md border border-gray-200 bg-white p-5">
            <p class="text-sm text-gray-700 mb-3">La demo está lista.</p>
            <a href="index.php?action=dashboard"
               class="inline-block px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">Ir a la demo</a>
            <form method="POST" class="mt-5 pt-4 border-t border-gray-200"
                  onsubmit="return confirm('Esto borra la base y la recrea. ¿Continuar?');">
                <input type="hidden" name="force" value="1">
                <input type="hidden" name="seed" value="1">
                <button type="submit" class="text-sm text-red-700 hover:underline">
                    Reinstalar desde cero (borra los datos actuales)
                </button>
            </form>
        </div>
    <?php else: ?>
        <form method="POST" class="rounded-md border border-gray-200 bg-white p-5">
            <p class="text-sm text-gray-700 mb-4">
                Se ejecutará <code>todoapp.sql</code> para crear la base
                <strong><?php echo htmlspecialchars($status['database']); ?></strong> con sus
                <?php echo count(App\Installer::EXPECTED_TABLES); ?> tablas.
                <?php if ($status['database_exists']): ?>
                    <span class="block mt-2 text-red-700">
                        La base ya existe: la migración la elimina y la vuelve a crear.
                    </span>
                <?php endif; ?>
            </p>
            <label class="flex items-center gap-2 text-sm mb-4">
                <input type="checkbox" name="seed" value="1" checked>
                Cargar datos de demostración (usuarios, proyectos, tareas, etiquetas y notas)
            </label>
            <?php if ($status['database_exists']): ?>
                <input type="hidden" name="force" value="1">
            <?php endif; ?>
            <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">
                Instalar base de datos
            </button>
        </form>
    <?php endif; ?>

    <p class="text-xs text-gray-500 mt-6">
        También por consola: <code>php example/install.php</code>
        (<code>--status</code>, <code>--force</code>, <code>--no-seed</code>)
    </p>
</div>
</body>
</html>
