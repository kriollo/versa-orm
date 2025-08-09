<?php

declare(strict_types=1);

namespace App\Models;

/**
 * Modelo User
 * Gestiona usuarios del sistema.
 */
class User extends BaseModel
{
    protected string $table = 'users';

    protected array $fillable = [
        'name',
        'email',
        'avatar_color',
        'active',
    ];

    protected array $guarded = [];

    protected array $rules = [
        'name'  => ['required', 'min:2', 'max:100'],
        'email' => ['required', 'email', 'max:150'],
    ];

    /**
     * Buscar por ID.
     */
    public static function find($id): ?self
    {
        return static::findOne('users', (int) $id);
    }

    /**
     * Obtener todos los usuarios.
     */
    public static function all(): array
    {
        return static::findAll('users');
    }

    /**
     * Crear nuevo usuario.
     */
    public static function create(array $attributes): static
    {
        // Aplicar valores por defecto
        if (!isset($attributes['avatar_color'])) {
            $attributes['avatar_color'] = static::generateRandomColor();
        }

        // Validar antes de crear
        $errors = [];
        if (empty($attributes['name'])) {
            $errors[] = 'El nombre es requerido';
        }
        if (empty($attributes['email'])) {
            $errors[] = 'El email es requerido';
        }
        if (!filter_var($attributes['email'], FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Email inválido';
        }

        if (!empty($errors)) {
            throw new \Exception('Errores de validación: ' . implode(', ', $errors));
        }

        // Crear instancia correctamente con el nombre de tabla
        $user = new static('users', static::orm());
        $user->fill($attributes);
        $user->store();
        return $user;
    }

    /**
     * Generar color aleatorio para avatar.
     */
    private static function generateRandomColor(): string
    {
        $colors = [
            '#ff6b6b',
            '#4ecdc4',
            '#45b7d1',
            '#96ceb4',
            '#ffeaa7',
            '#dda0dd',
            '#98d8c8',
            '#fdcb6e',
            '#6c5ce7',
            '#fd79a8',
            '#e17055',
            '#00b894',
            '#0984e3',
            '#a29bfe',
            '#fd79a8',
        ];
        return $colors[array_rand($colors)];
    }

    /**
     * Obtener proyectos del usuario (donde es miembro o propietario).
     */
    public function projects(): array
    {
        try {
            $allProjects = [];

            // Proyectos donde es propietario
            $ownedProjects = static::orm()->table('projects')
                ->where('owner_id', '=', $this->id)
                ->get();

            if ($ownedProjects) {
                $allProjects = array_merge($allProjects, $ownedProjects);
            }

            // Proyectos donde es miembro
            $memberProjects = static::orm()->table('projects')
                ->join('project_users', 'projects.id', '=', 'project_users.project_id')
                ->where('project_users.user_id', '=', $this->id)
                ->select(['projects.*'])
                ->get();

            if ($memberProjects) {
                $allProjects = array_merge($allProjects, $memberProjects);
            }

            // Eliminar duplicados basado en ID
            $uniqueProjects = [];
            $seenIds        = [];

            foreach ($allProjects as $project) {
                $projectId = isset($project['id']) ? $project['id'] : null;
                if ($projectId && !in_array($projectId, $seenIds)) {
                    $uniqueProjects[] = $project;
                    $seenIds[]        = $projectId;
                }
            }

            return $uniqueProjects;
        } catch (\Exception $e) {
            // Si falla el join, intentar solo los proyectos propios
            try {
                $projects = static::orm()->table('projects')
                    ->where('owner_id', '=', $this->id)
                    ->get();
                return $projects ?: [];
            } catch (\Exception $e2) {
                return [];
            }
        }
    }

    /**
     * Obtener tareas asignadas al usuario.
     */
    public function tasks(): array
    {
        try {
            $tasks = static::orm()->table('tasks')
                ->where('user_id', '=', $this->id)
                ->orderBy('created_at', 'desc')
                ->get();

            return $tasks ?: [];
        } catch (\Exception $e) {
            return [];
        }
    }

    /**
     * Obtener estadísticas del usuario.
     */
    public function getStats(): array
    {
        try {
            $projects       = $this->projects();
            $tasks          = $this->tasks();
            $completedTasks = array_filter($tasks, function ($task) {
                return isset($task['status']) && $task['status'] === 'done';
            });

            return [
                'projects_count'        => count($projects),
                'tasks_count'           => count($tasks),
                'completed_tasks_count' => count($completedTasks),
                'completion_rate'       => count($tasks) > 0 ? (count($completedTasks) / count($tasks)) * 100 : 0,
                'projects'              => $projects,
                'tasks'                 => $tasks,
                'completed_tasks'       => $completedTasks,
            ];
        } catch (\Exception $e) {
            return [
                'projects_count'        => 0,
                'tasks_count'           => 0,
                'completed_tasks_count' => 0,
                'completion_rate'       => 0,
                'projects'              => [],
                'tasks'                 => [],
                'completed_tasks'       => [],
            ];
        }
    }

    /**
     * Definir tipos de propiedades para validación y casting.
     */
    public static function definePropertyTypes(): array
    {
        return [
            'id'           => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name'         => ['type' => 'string', 'max_length' => 100, 'nullable' => false],
            'email'        => ['type' => 'string', 'max_length' => 150, 'nullable' => false, 'unique' => true],
            'avatar_color' => ['type' => 'string', 'max_length' => 7, 'nullable' => true, 'default' => '#3498db'],
            'active'       => ['type' => 'bool', 'nullable' => false, 'default' => true],
            'created_at'   => ['type' => 'datetime', 'nullable' => false],
            'updated_at'   => ['type' => 'datetime', 'nullable' => false],
        ];
    }
}
