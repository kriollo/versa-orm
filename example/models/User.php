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
    protected array $fillable = [
        'name',
        'email'
    ];

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
