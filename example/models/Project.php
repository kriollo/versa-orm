<?php

namespace Example\Models;

/**
 * Modelo Project - Gestión de proyectos
 *
 * Campos de la tabla 'projects':
 * - id: int (PK, auto_increment)
 * - name: string (required)
 * - description: text (optional)
 * - created_at: timestamp
 * - updated_at: timestamp
 */
class Project extends BaseModel
{
    /**
     * Nombre de la tabla
     */
    protected string $table = 'projects';

    /**
     * Campos que se pueden asignar masivamente
     */
    protected array $fillable = [
        'name',
        'description'
    ];

    /**
     * Relación: un proyecto tiene muchas tareas
     * @return array<int, array<string, mixed>>
     */
    public function tasksArray(): array
    {
        return Task::whereArray('project_id', '=', $this->id);
    }

    /**
     * Relación: un proyecto tiene muchas tareas (objetos)
     * @return Task[]
     */
    public function tasks(): array
    {
        return Task::where('project_id', '=', $this->id);
    }

    /**
     * Relación: un proyecto pertenece a un usuario
     * @return array<string, mixed>|null
     */
    public function userArray(): ?array
    {
        if (empty($this->user_id)) return null;
        return User::whereArray('id', '=', $this->user_id)[0] ?? null;
    }

    /**
     * Relación: un proyecto tiene muchas tareas (belongsToMany ficticio)
     * @return array<int, array<string, mixed>>
     */
    public function tasksManyToManyArray(): array
    {
        // Ejemplo de belongsToMany usando SQL crudo
        $sql = "SELECT t.* FROM tasks t JOIN project_task pt ON pt.task_id = t.id WHERE pt.project_id = ?";
        return $this->db->exec($sql, [$this->id]);
    }

    /**
     * Ejemplo de uso de QueryBuilder avanzado: tareas completadas de este proyecto
     * @return array<int, array<string, mixed>>
     */
    public function completedTasksArray(): array
    {
        return $this->db->table('tasks')
            ->where('project_id', '=', $this->id)
            ->where('completed', '=', 1)
            ->orderBy('created_at', 'DESC')
            ->get();
    }

    /**
     * Ejemplo de agregados: contar tareas
     */
    public function countTasks(): int
    {
        return $this->db->table('tasks')->where('project_id', '=', $this->id)->count();
    }

    /**
     * Ejemplo de uso de caché
     */
    public function cacheStatus(): mixed
    {
        return $this->db->cache('status');
    }

    /**
     * Ejemplo de transacción: marcar todas las tareas como completadas
     */
    public function completeAllTasks(): void
    {
        $this->db->exec('START TRANSACTION');
        try {
            $this->db->exec('UPDATE tasks SET completed = 1 WHERE project_id = ?', [$this->id]);
            $this->db->exec('COMMIT');
        } catch (\Exception $e) {
            $this->db->exec('ROLLBACK');
            throw $e;
        }
    }
}
