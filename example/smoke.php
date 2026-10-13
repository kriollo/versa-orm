<?php

declare(strict_types=1);

/**
 * Smoke test de la demo.
 *
 * Recorre la aplicación de ejemplo de punta a punta y sale con código 1 si algo falla.
 * Cubre dos capas:
 *
 *   1. Modelos y relaciones, llamando directamente a la API del ORM.
 *   2. Rutas HTTP, levantando el servidor embebido de PHP y pidiendo cada una.
 *
 * Existe porque CI no ejecutaba nada del ejemplo salvo el chequeo de estilo: un fallo
 * funcional aquí (una relación mal declarada, un método inexistente) no lo detectaba
 * nadie.
 *
 *     php example/smoke.php             # instala la base si hace falta y prueba todo
 *     php example/smoke.php --no-http   # sólo la capa de modelos
 */

use App\Installer;
use App\Models\Task;

require_once __DIR__ . '/../vendor/autoload.php';

$args = array_slice($argv ?? [], 1);
$skipHttp = in_array('--no-http', $args, true);

$config = require __DIR__ . '/app/config.php';

// ---------------------------------------------------------------------------
// Preparar la base: el smoke test debe poder correr sobre una instalación limpia
// ---------------------------------------------------------------------------
require_once __DIR__ . '/app/Installer.php';
$installer = Installer::fromConfig($config);
$status = $installer->status();

if (!$status['server_reachable']) {
    fwrite(STDERR, "No hay conexión con MySQL: {$status['server_error']}\n");
    exit(1);
}
echo "Preparando base de datos…\n";
$installer->runMigration(true);
$installer->seedDemoData();
echo "  base instalada con datos de demostración\n\n";

// El bootstrap arranca sesión y define los helpers; se carga después de instalar
// porque crea el ORM contra una base que tiene que existir.
require_once __DIR__ . '/app/bootstrap.php';

$passed = 0;
$failed = [];

/** Ejecuta una comprobación y registra el resultado. */
function check(string $label, callable $fn): mixed
{
    global $passed, $failed;

    try {
        $result = $fn();
        $passed++;
        echo "  ok    {$label}\n";

        return $result;
    } catch (Throwable $e) {
        $failed[] = $label . ' => ' . $e::class . ': ' . explode("\n", $e->getMessage())[0];
        echo "  FALLA {$label}\n";

        return null;
    }
}

/**
 * Comprueba una condición.
 *
 * Recibe un callable y no un bool para que la condición se evalúe DENTRO del try: si se
 * pasara ya evaluada, una excepción al construirla (una relación rota, por ejemplo)
 * escaparía del manejo de errores y abortaría la corrida entera en vez de registrarse
 * como una falla más.
 */
function expect(string $label, callable $condition, string $detail = ''): void
{
    check($label, static function () use ($condition, $detail): bool {
        if ($condition() !== true) {
            throw new RuntimeException($detail !== '' ? $detail : 'condición no cumplida');
        }

        return true;
    });
}

// ---------------------------------------------------------------------------
// 1. Modelos, relaciones y operaciones
// ---------------------------------------------------------------------------
echo "Modelos y relaciones\n";

$suffix = bin2hex(random_bytes(4));
$u1 = check('crear usuario', fn() => models()->user()->createOne(
    ['name' => 'Smoke Uno', 'email' => "uno.{$suffix}@smoke.local", 'avatar_color' => '#ff0000'],
));
$u2 = check('crear segundo usuario', fn() => models()->user()->createOne(
    ['name' => 'Smoke Dos', 'email' => "dos.{$suffix}@smoke.local", 'avatar_color' => '#00ff00'],
));
$uid1 = $u1->id ?? 0;
$uid2 = $u2->id ?? 0;

check('listar usuarios', fn() => models()->user()->all());
expect('el usuario se recupera por id', static fn(): bool => models()->user()->find($uid1)?->name === 'Smoke Uno');
check('estadísticas de usuario', fn() => models()->user()->find($uid1)->getStats());

$project = check('crear proyecto', fn() => models()->project()->createOne(
    ['name' => "Smoke {$suffix}", 'description' => 'demo', 'color' => '#3498db', 'owner_id' => $uid1],
));
$pid = $project->id ?? 0;

check('agregar miembro al proyecto', fn() => models()->project()->find($pid)->addMember($uid2));
expect(
    'el miembro aparece en la relación',
    static fn(): bool => count(models()->project()->find($pid)->members()->getResults()) === 1,
);

$label = check('crear etiqueta', fn() => models()->label()->createOne(
    ['name' => "Etq {$suffix}", 'color' => '#e74c3c', 'description' => 'demo'],
));
$lid = $label->id ?? 0;

$task = check('crear tarea', fn() => models()->task()->createOne([
    'title' => 'Tarea de smoke',
    'description' => 'demo',
    'project_id' => $pid,
    'user_id' => $uid1,
    'status' => 'todo',
    'priority' => 'high',
    'due_date' => '2099-12-31',
]));
$tid = $task->id ?? 0;

check('cambiar estado de la tarea', fn() => models()->task()->find($tid)->changeStatus('in_progress'));
expect('el estado quedó guardado', static fn(): bool => models()->task()->find($tid)->status === 'in_progress');

check('reasignar la tarea', fn() => models()->task()->find($tid)->assignUser($uid2));
expect('la asignación quedó guardada', static fn(): bool => (int) models()->task()->find($tid)->user_id === $uid2);

check('adjuntar etiqueta', fn() => models()->task()->find($tid)->attachLabel($lid));
expect('la etiqueta quedó adjunta', static fn(): bool => models()->task()->find($tid)->getLabelIds() !== []);
check('sincronizar etiquetas', fn() => models()->task()->find($tid)->syncLabels([$lid]));
check('setLabels', fn() => models()->task()->find($tid)->setLabels([$lid]));

expect('la tarea no está vencida', static fn(): bool => models()->task()->find($tid)->isOverdue() === false);
check('tareas recientes', fn() => Task::getRecent(5));
check('contar tareas', fn() => Task::countAll());
check('contar pendientes', fn() => Task::countPending());

// Relaciones en ambos sentidos
expect(
    'tarea -> proyecto',
    static fn(): bool => models()->task()->find($tid)->project()->getResults()?->id === $pid,
    'belongsTo con las claves invertidas consulta una columna inexistente',
);
expect('tarea -> usuario', static fn(): bool => models()->task()->find($tid)->user()->getResults()?->id === $uid2);
expect('tarea -> etiquetas', static fn(): bool => count(models()->task()->find($tid)->labels()->getResults()) === 1);
expect('proyecto -> tareas', static fn(): bool => count(models()->project()->find($pid)->tasks()->getResults()) === 1);
expect('proyecto -> dueño', static fn(): bool => models()->project()->find($pid)->owner()->getResults()?->id === $uid1);
expect('usuario -> tareas (relación)', static fn(): bool => count(models()->user()->find($uid2)->tasksRelation()->getResults()) === 1);
expect('usuario -> tareas (array)', static fn(): bool => count(models()->user()->find($uid2)->tasks()) === 1);
expect('usuario -> proyectos', static fn(): bool => is_array(models()->user()->find($uid1)->projects()));

$note = check('crear nota', fn() => models()->note()->createOne(
    ['content' => 'Nota de smoke', 'task_id' => $tid, 'user_id' => $uid1],
));
expect('tarea -> notas', static fn(): bool => count(models()->task()->find($tid)->notes()->getResults()) === 1);

// Limpieza, que también ejercita los borrados
check('separar etiqueta', fn() => models()->task()->find($tid)->detachLabel($lid));
check('quitar miembro', fn() => models()->project()->find($pid)->removeMember($uid2));
check('borrar nota', fn() => models()->note()->find($note->id ?? 0)?->trash());
check('borrar tarea', fn() => models()->task()->find($tid)->trash());
check('borrar etiqueta', fn() => models()->label()->find($lid)->trash());
check('borrar proyecto', fn() => models()->project()->find($pid)->trash());
check('borrar usuarios', function () use ($uid1, $uid2): bool {
    models()->user()->find($uid1)->trash();
    models()->user()->find($uid2)->trash();

    return true;
});

// ---------------------------------------------------------------------------
// 2. Rutas HTTP
// ---------------------------------------------------------------------------
if (!$skipHttp) {
    echo "\nRutas HTTP\n";
    $port = 8123;
    $root = __DIR__;
    $descriptors = [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
    $server = proc_open(
        sprintf('exec php -S 127.0.0.1:%d -t %s', $port, escapeshellarg($root)),
        $descriptors,
        $pipes,
    );

    if (!is_resource($server)) {
        fwrite(STDERR, "No se pudo levantar el servidor embebido\n");
        exit(1);
    }

    // Esperar a que acepte conexiones
    for ($i = 0; $i < 50; $i++) {
        $probe = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);

        if ($probe !== false) {
            fclose($probe);
            break;
        }
        usleep(100_000);
    }

    $base = sprintf('http://127.0.0.1:%d', $port);
    // allArray() y no all(): esta última devuelve modelos, no filas.
    $firstId = static fn(array $rows): int => (int) ($rows[0]['id'] ?? 0);
    $ids = [
        'project' => $firstId(models()->project()->allArray()),
        'task' => $firstId(models()->task()->allArray()),
        'user' => $firstId(models()->user()->allArray()),
        'label' => $firstId(models()->label()->allArray()),
    ];

    $routes = [
        'dashboard' => '/index.php?action=dashboard',
        'proyectos' => '/index.php?action=projects',
        'ver proyecto' => '/index.php?action=project_show&id=' . $ids['project'],
        'form proyecto' => '/index.php?action=project_create',
        'editar proyecto' => '/index.php?action=project_edit&id=' . $ids['project'],
        'tareas' => '/index.php?action=tasks',
        'form tarea' => '/index.php?action=task_create',
        'editar tarea' => '/index.php?action=task_edit&id=' . $ids['task'],
        'usuarios' => '/index.php?action=users',
        'form usuario' => '/index.php?action=user_create',
        'editar usuario' => '/index.php?action=user_edit&id=' . $ids['user'],
        'etiquetas' => '/index.php?action=labels',
        'form etiqueta' => '/index.php?action=label_create',
        'editar etiqueta' => '/index.php?action=label_edit&id=' . $ids['label'],
        'tareas de etiqueta' => '/index.php?action=label_tasks&id=' . $ids['label'],
        'instalador' => '/install.php',
        'api proyectos' => '/app/api.php?resource=projects',
        'api tareas' => '/app/api.php?resource=tasks',
        'api usuarios' => '/app/api.php?resource=users',
        'api etiquetas' => '/app/api.php?resource=labels',
        'api notas' => '/app/api.php?resource=notes',
        'ajax notas' => '/app/notes_ajax.php?action=get_notes&task_id=' . $ids['task'],
    ];

    foreach ($routes as $label => $path) {
        check($label, static function () use ($base, $path): bool {
            $body = @file_get_contents($base . $path);

            if ($body === false) {
                throw new RuntimeException('sin respuesta');
            }

            // El router captura las excepciones y las pinta, así que un HTTP 200 no
            // basta: hay que mirar el contenido.
            foreach (['Fatal error', 'Uncaught', 'Error del sistema', 'Vista no encontrada'] as $needle) {
                if (str_contains($body, $needle)) {
                    throw new RuntimeException($needle . ' en la respuesta');
                }
            }

            return true;
        });
    }

    // Las respuestas JSON deben serlo de verdad: las columnas datetime se castean a
    // objetos DateTime y, sin formatear, json_encode vuelca su estructura interna.
    check('la API devuelve JSON válido con fechas legibles', static function () use ($base): bool {
        $raw = @file_get_contents($base . '/app/api.php?resource=projects');
        $data = json_decode((string) $raw, true);

        if (!is_array($data) || $data === []) {
            throw new RuntimeException('respuesta no es un JSON con filas');
        }

        if (isset($data[0]['created_at']) && !is_string($data[0]['created_at'])) {
            throw new RuntimeException('created_at no es una cadena (¿objeto DateTime sin formatear?)');
        }

        return true;
    });

    proc_terminate($server);
    proc_close($server);
}

// ---------------------------------------------------------------------------
echo "\n";

if ($failed !== []) {
    printf("FALLÓ: %d ok, %d fallas\n\n", $passed, count($failed));

    foreach ($failed as $f) {
        echo "  - {$f}\n";
    }
    echo "\n";
    exit(1);
}
printf("OK: %d comprobaciones\n", $passed);
exit(0);
