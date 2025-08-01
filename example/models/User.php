<?php

namespace Example\Models;

/**
 * Modelo User - Gestión de usuarios (ficticio para demo avanzada)
 *
 * Campos de la tabla 'usuarios':
 * - id: int (PK, auto_increment)
 * - name: string (required)
 * - email: string (required)
 * - created_at: timestamp
 * - updated_at: timestamp
 */
class User extends BaseModel
{
    protected string $table = 'usuarios';

    /**
     * Campos permitidos para Mass Assignment
     * @var array<string>
     */
    protected array $fillable = [
        'name',
        'email'
    ];

    /**
     * Reglas de validación personalizadas
     * @var array<string, array<string>>
     */
    protected array $rules = [
        'name' => ['required', 'min:2', 'max:50'],
        'email' => ['required', 'email']
    ];

    /**
     * Método de negocio: verificar si el usuario tiene proyectos activos
     * @return bool
     */
    public function hasActiveProjects(): bool
    {
        $activeProjects = $this->db->table('projects')
            ->where('user_id', '=', $this->id)
            ->where('status', '=', 'active')
            ->count();

        return $activeProjects > 0;
    }

    /**
     * Relación: un usuario tiene muchos proyectos
     * @return array<int, array<string, mixed>>
     */
    public function projectsArray(): array
    {
        return Project::whereArray('user_id', '=', $this->id);
    }

    /**
     * Relación: un usuario tiene muchas tareas (a través de proyectos)
     * @return array<int, array<string, mixed>>
     */
    public function tasksArray(): array
    {
        // Ejemplo de join avanzado con QueryBuilder
        $instance = new static();
        return $instance->db->table('tasks')
            ->join('projects', 'tasks.project_id', '=', 'projects.id')
            ->where('projects.user_id', '=', $this->id)
            ->get();
    }
}
