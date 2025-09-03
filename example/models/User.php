<?php

declare(strict_types=1);

namespace App\Models;

use App\BaseModel;
use Exception;

use function count;
use function in_array;

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
        'name' => ['required', 'min:2', 'max:100'],
        'email' => ['required', 'email', 'max:150'],
    ];

    /** Obtener el conteo total de usuarios. */
    public static function countAll(): int
    {
        return self::queryTable()->count();
    }

    /** Relación N:M: proyectos donde el usuario es miembro (BelongsToMany). */
    public function projectsRelation(): \VersaORM\Relations\BelongsToMany
    {
        return $this->belongsToMany(Project::class, 'project_users', 'user_id', 'project_id', 'id', 'id');
    }

    /** Adjuntar usuario a un proyecto (como miembro). */
    public function attachProject(int $projectId): void
    {
        $this->projectsRelation()->attach($projectId);
    }

    /** Separar usuario de un proyecto (como miembro). */
    public function detachProject(int $projectId): void
    {
        $this->projectsRelation()->detach($projectId);
    }

    /** Sincronizar proyectos del usuario (N:M). */
    public function syncProjects(array $projectIds): array
    {
        return $this->projectsRelation()->sync($projectIds);
    }

    /** Recargar el usuario desde la base de datos (fresh). */
    /** Recargar el usuario desde la base de datos (fresh). */
    public function fresh(string $primaryKey = 'id'): static
    {
        return parent::fresh($primaryKey);
    }

    /** Crear usuario con defaults y casting consistente (instancia). */
    public function createOne(array $attributes): self
    {
        if (!isset($attributes['avatar_color'])) {
            $attributes['avatar_color'] = $this->generateRandomColor();
        }
        $this->fill($attributes);
        $this->store();

        return $this;
    }

    /**
     * Obtener proyectos del usuario (donde es miembro o propietario).
     */
    public function projects(): array
    {
        try {
            $allProjects = [];

            // Proyectos donde es propietario
            $ownedProjects = $this->getOrm()
                ->table('projects', Project::class)
                ->where('owner_id', '=', $this->id)
                ->get();

            if ($ownedProjects) {
                $allProjects = array_merge($allProjects, $ownedProjects);
            }

            // Proyectos donde es miembro
            $memberProjects = $this->getOrm()
                ->table('projects', Project::class)
                ->join('project_users', 'projects.id', '=', 'project_users.project_id')
                ->where('project_users.user_id', '=', $this->id)
                ->select(['projects.*'])
                ->get();

            if ($memberProjects) {
                $allProjects = array_merge($allProjects, $memberProjects);
            }

            // Eliminar duplicados basado en ID
            $uniqueProjects = [];
            $seenIds = [];

            foreach ($allProjects as $project) {
                $projectId = $project['id'] ?? null;

                if ($projectId && !in_array($projectId, $seenIds, true)) {
                    $uniqueProjects[] = $project;
                    $seenIds[] = $projectId;
                }
            }

            return $uniqueProjects;
        } catch (Exception) {
            // Si falla el join, intentar solo los proyectos propios
            try {
                $projects = $this->getOrm()
                    ->table('projects', Project::class)
                    ->where('owner_id', '=', $this->id)
                    ->get();

                return $projects ?: [];
            } catch (Exception) {
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
            $tasks = $this->getOrm()
                ->table('tasks', Task::class)
                ->where('user_id', '=', $this->id)
                ->orderBy('created_at', 'desc')
                ->get();

            return $tasks ?: [];
        } catch (Exception) {
            return [];
        }
    }

    /**
     * Obtener estadísticas del usuario.
     */
    public function getStats(): array
    {
        try {
            $projects = $this->projects();
            $tasks = $this->tasks();
            $completedTasks = array_filter(
                $tasks,
                static fn ($task): bool => isset($task['status']) && $task['status'] === 'done',
            );

            return [
                'projects_count' => count($projects),
                'tasks_count' => count($tasks),
                'completed_tasks_count' => count($completedTasks),
                'completion_rate' => $tasks !== [] ? (count($completedTasks) / count($tasks)) * 100 : 0,
                'projects' => $projects,
                'tasks' => $tasks,
                'completed_tasks' => $completedTasks,
            ];
        } catch (Exception) {
            return [
                'projects_count' => 0,
                'tasks_count' => 0,
                'completed_tasks_count' => 0,
                'completion_rate' => 0,
                'projects' => [],
                'tasks' => [],
                'completed_tasks' => [],
            ];
        }
    }

    /**
     * Definir tipos de propiedades para validación y casting.
     */
    public static function definePropertyTypes(): array
    {
        return [
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name' => ['type' => 'string', 'max_length' => 100, 'nullable' => false],
            'email' => ['type' => 'string', 'max_length' => 150, 'nullable' => false, 'unique' => true],
            'avatar_color' => ['type' => 'string', 'max_length' => 7, 'nullable' => true, 'default' => '#3498db'],
            'active' => ['type' => 'bool', 'nullable' => false, 'default' => true],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
            'updated_at' => ['type' => 'datetime', 'nullable' => false],
        ];
    }

    /**
     * Generar color aleatorio para avatar.
     */
    private function generateRandomColor(): string
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
}
