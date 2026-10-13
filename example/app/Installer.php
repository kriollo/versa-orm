<?php

declare(strict_types=1);

namespace App;

use PDO;
use PDOException;
use RuntimeException;
use Throwable;

/**
 * Instalador de la base de datos de la demo.
 *
 * Permite arrancar el ejemplo sin preparar nada a mano: detecta si la base existe y
 * tiene las tablas esperadas y, si no, ejecuta la migración `todoapp.sql` y carga datos
 * de demostración.
 *
 * Se conecta con PDO directamente y no con VersaORM a propósito: cuando la base todavía
 * no existe, el ORM no puede establecer conexión.
 */
final class Installer
{
    /** Tablas que la migración debe dejar creadas. */
    public const EXPECTED_TABLES = [
        'users',
        'projects',
        'labels',
        'tasks',
        'project_users',
        'task_labels',
        'task_notes',
    ];

    /** @param array<string, mixed> $dbConfig La sección 'database' de config.php */
    public function __construct(private array $dbConfig) {}

    public static function fromConfig(array $appConfig): self
    {
        return new self($appConfig['database'] ?? []);
    }

    public function databaseName(): string
    {
        return (string) ($this->dbConfig['database'] ?? '');
    }

    /** ¿Existe la base de datos? */
    public function databaseExists(): bool
    {
        try {
            $stmt = $this->serverConnection()->prepare(
                'SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?',
            );
            $stmt->execute([$this->databaseName()]);

            return $stmt->fetchColumn() !== false;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Tablas que faltan respecto de EXPECTED_TABLES.
     *
     * @return list<string>
     */
    public function missingTables(): array
    {
        if (!$this->databaseExists()) {
            return self::EXPECTED_TABLES;
        }

        try {
            $existing = $this->databaseConnection()
                ->query('SHOW TABLES')
                ->fetchAll(PDO::FETCH_COLUMN);
        } catch (Throwable) {
            return self::EXPECTED_TABLES;
        }
        $existing = array_map('strtolower', array_map('strval', $existing));

        return array_values(array_filter(
            self::EXPECTED_TABLES,
            static fn(string $t): bool => !in_array($t, $existing, true),
        ));
    }

    /** La demo puede arrancar: la base existe y están todas las tablas. */
    public function isInstalled(): bool
    {
        return $this->missingTables() === [];
    }

    /** ¿Hay algún dato cargado? Se usa para no ofrecer el sembrado dos veces. */
    public function hasData(): bool
    {
        if (!$this->isInstalled()) {
            return false;
        }

        try {
            return (int) $this->databaseConnection()
                ->query('SELECT COUNT(*) FROM users')
                ->fetchColumn() > 0;
        } catch (Throwable) {
            return false;
        }
    }

    public function migrationPath(): string
    {
        return dirname(__DIR__) . '/todoapp.sql';
    }

    /**
     * Ejecuta `todoapp.sql`.
     *
     * El archivo incluye `DROP DATABASE`, así que es destructivo: sólo se ejecuta cuando
     * la demo no está instalada, salvo que se pase $force explícitamente.
     *
     * @return list<string> pasos realizados, para mostrarlos al usuario
     */
    public function runMigration(bool $force = false): array
    {
        if (!$force && $this->isInstalled()) {
            throw new RuntimeException(
                'La base ya está instalada. Usa la reinstalación explícita si quieres recrearla '
                . '(se perderán los datos).',
            );
        }
        $path = $this->migrationPath();

        if (!is_readable($path)) {
            throw new RuntimeException(sprintf('No se encuentra la migración: %s', $path));
        }
        $sql = file_get_contents($path);

        if ($sql === false || trim($sql) === '') {
            throw new RuntimeException('La migración está vacía o no se pudo leer.');
        }

        // El volcado nombra la base explícitamente (DROP/CREATE DATABASE y USE). Si la
        // configuración apunta a otro nombre —por ejemplo vía DEMO_DB_NAME— hay que
        // reescribirlo, o la migración crearía la base equivocada y la app no
        // encontraría sus tablas.
        $sql = $this->retargetDatabaseName($sql);

        try {
            $this->serverConnection()->exec($sql);
        } catch (PDOException $e) {
            throw new RuntimeException('Falló la migración: ' . $e->getMessage(), 0, $e);
        }
        $missing = $this->missingTables();

        if ($missing !== []) {
            throw new RuntimeException(
                'La migración se ejecutó pero faltan tablas: ' . implode(', ', $missing),
            );
        }

        return [
            sprintf('Migración ejecutada: %s', basename($path)),
            sprintf('Base «%s» con %d tablas', $this->databaseName(), count(self::EXPECTED_TABLES)),
        ];
    }

    /** Nombre de la base que trae escrito el volcado. */
    private const DUMP_DATABASE = 'versaorm_trello';

    /** Reescribe el nombre de la base en el volcado para que coincida con la config. */
    private function retargetDatabaseName(string $sql): string
    {
        $target = $this->databaseName();

        if ($target === '' || $target === self::DUMP_DATABASE) {
            return $sql;
        }

        return str_replace(
            ['`' . self::DUMP_DATABASE . '`', ' ' . self::DUMP_DATABASE . ' '],
            ['`' . $target . '`', ' ' . $target . ' '],
            $sql,
        );
    }

    /**
     * Carga datos de demostración.
     *
     * `todoapp.sql` sólo trae el esquema, así que sin esto la demo arranca vacía y no se
     * puede ver nada funcionando. Se usa SQL parametrizado y no el ORM porque el
     * instalador tiene que poder correr antes de que el ORM esté operativo.
     *
     * @return list<string>
     */
    public function seedDemoData(): array
    {
        if (!$this->isInstalled()) {
            throw new RuntimeException('No se puede sembrar: la base no está instalada.');
        }
        $pdo = $this->databaseConnection();
        $pdo->beginTransaction();

        try {
            $users = [
                ['Ana Soto', 'ana@demo.local', '#e74c3c'],
                ['Beto Díaz', 'beto@demo.local', '#3498db'],
                ['Carla Ruiz', 'carla@demo.local', '#2ecc71'],
            ];
            $userIds = [];
            $insUser = $pdo->prepare('INSERT INTO users (name, email, avatar_color) VALUES (?, ?, ?)');

            foreach ($users as $u) {
                $insUser->execute($u);
                $userIds[] = (int) $pdo->lastInsertId();
            }

            $labels = [
                ['Urgente', '#e74c3c', 'Requiere atención inmediata'],
                ['Mejora', '#3498db', 'Mejora incremental'],
                ['Bug', '#e67e22', 'Defecto a corregir'],
                ['Documentación', '#9b59b6', 'Falta documentar'],
            ];
            $labelIds = [];
            $insLabel = $pdo->prepare('INSERT INTO labels (name, color, description) VALUES (?, ?, ?)');

            foreach ($labels as $l) {
                $insLabel->execute($l);
                $labelIds[] = (int) $pdo->lastInsertId();
            }

            $projects = [
                ['Rediseño del portal', 'Renovar la interfaz pública', '#3498db', $userIds[0]],
                ['Migración a VersaORM', 'Reemplazar el acceso a datos legado', '#2ecc71', $userIds[1]],
            ];
            $projectIds = [];
            $insProject = $pdo->prepare(
                'INSERT INTO projects (name, description, color, owner_id) VALUES (?, ?, ?, ?)',
            );

            foreach ($projects as $p) {
                $insProject->execute($p);
                $projectIds[] = (int) $pdo->lastInsertId();
            }

            // Miembros de los proyectos (tabla pivote)
            $insMember = $pdo->prepare('INSERT INTO project_users (project_id, user_id) VALUES (?, ?)');

            foreach ([[0, 1], [0, 2], [1, 0], [1, 2]] as [$pi, $ui]) {
                $insMember->execute([$projectIds[$pi], $userIds[$ui]]);
            }

            // Tareas repartidas entre los tres estados y las cuatro prioridades
            $tasks = [
                ['Auditar accesibilidad', 'Revisar contraste y navegación por teclado', 'todo', 'high', '+10 days', 0, 0],
                ['Maquetar portada', 'Nueva portada responsive', 'in_progress', 'medium', '+3 days', 0, 1],
                ['Definir paleta', 'Colores corporativos', 'done', 'low', '-5 days', 0, 2],
                ['Inventario de consultas', 'Listar el SQL a migrar', 'done', 'medium', '-2 days', 1, 1],
                ['Migrar módulo de usuarios', 'Pasar el CRUD a VersaORM', 'in_progress', 'urgent', '+1 day', 1, 0],
                ['Tarea vencida de ejemplo', 'Muestra el aviso de vencimiento', 'todo', 'high', '-7 days', 1, 2],
            ];
            $taskIds = [];
            $insTask = $pdo->prepare(
                'INSERT INTO tasks (title, description, status, priority, due_date, project_id, user_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?)',
            );

            foreach ($tasks as [$title, $desc, $status, $priority, $due, $pi, $ui]) {
                $insTask->execute([
                    $title,
                    $desc,
                    $status,
                    $priority,
                    date('Y-m-d', strtotime($due)),
                    $projectIds[$pi],
                    $userIds[$ui],
                ]);
                $taskIds[] = (int) $pdo->lastInsertId();
            }

            // Etiquetas de las tareas (tabla pivote)
            $insTaskLabel = $pdo->prepare('INSERT INTO task_labels (task_id, label_id) VALUES (?, ?)');

            foreach ([[0, 0], [0, 3], [1, 1], [3, 1], [4, 0], [4, 2], [5, 2]] as [$ti, $li]) {
                $insTaskLabel->execute([$taskIds[$ti], $labelIds[$li]]);
            }

            // Notas
            $insNote = $pdo->prepare('INSERT INTO task_notes (content, task_id, user_id) VALUES (?, ?, ?)');

            foreach ([
                ['Pendiente de validar con diseño.', 0, 0],
                ['Avanzado el 60%.', 1, 1],
                ['Bloqueado por el inventario de consultas.', 4, 0],
            ] as [$content, $ti, $ui]) {
                $insNote->execute([$content, $taskIds[$ti], $userIds[$ui]]);
            }

            $pdo->commit();
        } catch (Throwable $e) {
            $pdo->rollBack();

            throw new RuntimeException('Falló el sembrado de datos: ' . $e->getMessage(), 0, $e);
        }

        return [
            sprintf('%d usuarios', count($userIds)),
            sprintf('%d proyectos con sus miembros', count($projectIds)),
            sprintf('%d etiquetas', count($labelIds)),
            sprintf('%d tareas con etiquetas y notas', count($taskIds)),
        ];
    }

    /** Diagnóstico para la página de instalación y la CLI. */
    public function status(): array
    {
        $serverReachable = true;
        $serverError = null;

        try {
            $this->serverConnection();
        } catch (Throwable $e) {
            $serverReachable = false;
            $serverError = $e->getMessage();
        }

        return [
            'server_reachable' => $serverReachable,
            'server_error' => $serverError,
            'host' => (string) ($this->dbConfig['host'] ?? ''),
            'port' => (int) ($this->dbConfig['port'] ?? 3306),
            'database' => $this->databaseName(),
            'username' => (string) ($this->dbConfig['username'] ?? ''),
            'database_exists' => $serverReachable && $this->databaseExists(),
            'missing_tables' => $serverReachable ? $this->missingTables() : self::EXPECTED_TABLES,
            'installed' => $serverReachable && $this->isInstalled(),
            'has_data' => $serverReachable && $this->hasData(),
            'migration' => $this->migrationPath(),
            'migration_readable' => is_readable($this->migrationPath()),
        ];
    }

    /** Conexión al servidor, sin seleccionar base (necesaria para poder crearla). */
    private function serverConnection(): PDO
    {
        return new PDO(
            sprintf(
                'mysql:host=%s;port=%d;charset=%s',
                $this->dbConfig['host'] ?? '127.0.0.1',
                (int) ($this->dbConfig['port'] ?? 3306),
                $this->dbConfig['charset'] ?? 'utf8mb4',
            ),
            (string) ($this->dbConfig['username'] ?? ''),
            (string) ($this->dbConfig['password'] ?? ''),
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );
    }

    private function databaseConnection(): PDO
    {
        return new PDO(
            sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                $this->dbConfig['host'] ?? '127.0.0.1',
                (int) ($this->dbConfig['port'] ?? 3306),
                $this->databaseName(),
                $this->dbConfig['charset'] ?? 'utf8mb4',
            ),
            (string) ($this->dbConfig['username'] ?? ''),
            (string) ($this->dbConfig['password'] ?? ''),
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );
    }
}
