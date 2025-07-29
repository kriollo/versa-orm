<?php

namespace Example\Models;

/**
 * Modelo Task - Gestión de tareas
 *
 * Campos de la tabla 'tasks':
 * - id: int (PK, auto_increment)
 * - title: string (required)
 * - description: text (optional)
 * - completed: boolean (default: false)
 * - created_at: timestamp
 * - updated_at: timestamp
 */
class Task extends BaseModel
{
    /**
     * Nombre de la tabla
     */
    protected string $table = 'tasks';

    /**
     * Campos que se pueden asignar masivamente
     */
    protected array $fillable = [
        'title',
        'description',
        'completed'
    ];

    /**
     * Campos ocultos en la serialización (si los hubiera)
     */
    protected array $hidden = [];

    /**
     * Validación específica para tareas
     */
    public function validate(): array
    {
        $errors = [];

        // Título es requerido
        if (empty($this->title)) {
            $errors['title'] = 'El título es requerido';
        }

        // Título no debe ser muy largo
        if (strlen($this->title ?? '') > 255) {
            $errors['title'] = 'El título no puede tener más de 255 caracteres';
        }

        // Descripción no debe ser muy larga
        if (strlen($this->description ?? '') > 1000) {
            $errors['description'] = 'La descripción no puede tener más de 1000 caracteres';
        }

        return $errors;
    }

    /**
     * Obtiene tareas completadas usando QueryBuilder
     */
    public static function completed(): array
    {
        $instance = new static();
        return $instance->db->table($instance->table)
            ->where('completed', '=', 1)
            ->findAll();
    }

    /**
     * Obtiene tareas pendientes usando QueryBuilder
     */
    public static function pending(): array
    {
        $instance = new static();
        return $instance->db->table($instance->table)
            ->where('completed', '=', 0)
            ->findAll();
    }

    /**
     * Marca una tarea como completada
     */
    public function markAsCompleted(): bool
    {
        return $this->update(['completed' => true]);
    }

    /**
     * Marca una tarea como pendiente
     */
    public function markAsPending(): bool
    {
        return $this->update(['completed' => false]);
    }

    /**
     * Búsqueda específica en tareas (title y description)
     */
    public static function searchTasks(string $term): array
    {
        return self::search($term, ['title', 'description']);
    }

    /**
     * Obtiene estadísticas de tareas
     */
    public static function getStats(): array
    {
        $instance = new static();

        $total = $instance->db->table($instance->table)->count();
        $completed = $instance->db->table($instance->table)
            ->where('completed', '=', true)->count();
        $pending = $total - $completed;

        return [
            'total' => $total,
            'completed' => $completed,
            'pending' => $pending,
            'completion_rate' => $total > 0 ? round(($completed / $total) * 100, 2) : 0
        ];
    }

    /**
     * Scope para tareas recientes (últimos 7 días)
     */
    public static function recent(): array
    {
        $instance = new static();

        $sql = "SELECT * FROM {$instance->table}
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                ORDER BY created_at DESC";

        $results = $instance->db->exec($sql);

        $models = [];
        foreach ($results as $result) {
            $model = new static();
            $model->loadInstance($result);
            $models[] = $model;
        }

        return $models;
    }
}
