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
        'completed',
        'project_id' // <-- necesario para que se guarde
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
     * Búsqueda específica en tareas (title y description) que devuelve arrays asociativos
     */
    public static function searchTasksArray(string $term): array
    {
        return self::searchArray($term, ['title', 'description']);
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

    /**
     * Relación: una tarea tiene muchas etiquetas (muchos a muchos)
     * @return array<int, array<string, mixed>>
     */
    public function labelsArray(): array
    {
        $sql = "SELECT l.* FROM labels l JOIN task_label tl ON tl.label_id = l.id WHERE tl.task_id = ?";
        return $this->db->exec($sql, [$this->id]);
    }

    /**
     * Asigna una etiqueta a la tarea (si no existe la relación, la crea)
     */
    public function addLabel(int $labelId): void
    {
        // Verifica si ya existe
        $exists = $this->db->exec("SELECT id FROM task_label WHERE task_id = ? AND label_id = ?", [$this->id, $labelId]);
        if (empty($exists)) {
            $this->db->exec("INSERT INTO task_label (task_id, label_id) VALUES (?, ?)", [$this->id, $labelId]);
        }
    }

    /**
     * Quita una etiqueta de la tarea
     */
    public function removeLabel(int $labelId): void
    {
        $this->db->exec("DELETE FROM task_label WHERE task_id = ? AND label_id = ?", [$this->id, $labelId]);
    }

    /**
     * Reemplaza todas las etiquetas de la tarea por un nuevo set
     * @param int[] $labelIds
     */
    public function setLabels(array $labelIds): void
    {
        $this->db->exec("DELETE FROM task_label WHERE task_id = ?", [$this->id]);
        foreach ($labelIds as $labelId) {
            $this->addLabel($labelId);
        }
    }

    /**
     * Obtiene todas las tareas asociadas a una etiqueta (estático)
     * @param int $labelId
     * @return array<int, array<string, mixed>>
     */
    public static function byLabel(int $labelId): array
    {
        $instance = new static();
        $sql = "SELECT t.* FROM tasks t JOIN task_label tl ON tl.task_id = t.id WHERE tl.label_id = ?";
        return $instance->db->exec($sql, [$labelId]);
    }
}
