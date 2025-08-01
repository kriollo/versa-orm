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
     * @var array<string>
     */
    protected array $fillable = [
        'title',
        'description',
        'completed',
        'project_id'
    ];

    /**
     * Reglas de validación personalizadas
     * @var array<string, array<string>>
     */
    protected array $rules = [
        'title' => ['required', 'min:3', 'max:100'],
        'description' => ['max:500'],
        'project_id' => ['required', 'numeric']
    ];

    /**
     * Campos ocultos en la serialización (si los hubiera)
     * @var array<string>
     */
    protected array $hidden = [];

    /**
     * Método de negocio: marcar tarea como completada
     * @return bool
     */
    public function markAsCompleted(): bool
    {
        $this->completed = 1;
        $this->store();
        return true;
    }

    /**
     * Método de negocio: marcar tarea como pendiente
     * @return bool
     */
    public function markAsPending(): bool
    {
        $this->completed = 0;
        $this->store();
        return true;
    }

    /**
     * Scope: obtener tareas completadas
     * @return array<int, static>
     */
    public static function completed(): array
    {
        $instance = new static();
        return $instance->db->table($instance->table)
            ->where('completed', '=', 1)
            ->findAll();
    }

    /**
     * Scope: obtener tareas pendientes
     * @return array<int, static>
     */
    public static function pending(): array
    {
        $instance = new static();
        return $instance->db->table($instance->table)
            ->where('completed', '=', 0)
            ->findAll();
    }

    /**
     * Scope: obtener tareas por etiqueta (many-to-many)
     * @param int $labelId ID de la etiqueta
     * @return array<int, array<string, mixed>>
     */
    public static function byLabel(int $labelId): array
    {
        $instance = new static();
        $sql = "SELECT t.* FROM tasks t
                JOIN task_label tl ON tl.task_id = t.id
                WHERE tl.label_id = ?
                ORDER BY t.id DESC";
        return $instance->db->exec($sql, [$labelId]);
    }

    /**
     * Buscar tareas por título o descripción
     * @param string $term
     * @return array<int, static>
     */
    public static function searchTasks(string $term): array
    {
        $instance = new static();
        return $instance->db->table($instance->table)
            ->where('title', 'LIKE', "%{$term}%")
            ->orWhere('description', 'LIKE', "%{$term}%")
            ->findAll();
    }

    /**
     * Obtener estadísticas de tareas
     * @return array<string, mixed>
     */
    public static function getStats(): array
    {
        $instance = new static();
        $db = $instance->db;

        $total = $db->table($instance->table)->count();
        $completed = $db->table($instance->table)->where('completed', '=', 1)->count();
        $pending = $db->table($instance->table)->where('completed', '=', 0)->count();

        return [
            'total' => $total,
            'completed' => $completed,
            'pending' => $pending,
            'completion_rate' => $total > 0 ? round(($completed / $total) * 100, 2) : 0
        ];
    }

    /**
     * Obtener tareas recientes
     * @param int $limit
     * @return array<int, static>
     */
    public static function recent(int $limit = 10): array
    {
        $instance = new static();
        return $instance->db->table($instance->table)
            ->orderBy('created_at', 'DESC')
            ->limit($limit)
            ->findAll();
    }

    /**
     * Relación: obtener las etiquetas de esta tarea (many-to-many)
     * @return array<int, array<string, mixed>>
     */
    public function labelsArray(): array
    {
        return $this->db->table('labels')
            ->join('task_label', 'labels.id', '=', 'task_label.label_id')
            ->where('task_label.task_id', '=', $this->id)
            ->get();
    }

    /**
     * Asignar etiquetas a esta tarea (many-to-many)
     * @param array<int> $labelIds IDs de las etiquetas a asignar
     * @return void
     */
    public function setLabels(array $labelIds): void
    {
        if (!$this->id) {
            throw new \Exception('La tarea debe estar guardada antes de asignar etiquetas');
        }

        // Eliminar todas las etiquetas actuales
        $this->db->exec("DELETE FROM task_label WHERE task_id = ?", [$this->id]);

        // Asignar las nuevas etiquetas
        foreach ($labelIds as $labelId) {
            if (!empty($labelId)) {
                $this->db->exec(
                    "INSERT INTO task_label (task_id, label_id) VALUES (?, ?)",
                    [$this->id, $labelId]
                );
            }
        }
    }

    /**
     * Agregar una etiqueta a esta tarea
     * @param int $labelId ID de la etiqueta a agregar
     * @return void
     */
    public function addLabel(int $labelId): void
    {
        if (!$this->id) {
            throw new \Exception('La tarea debe estar guardada antes de agregar etiquetas');
        }

        // Verificar si la relación ya existe
        $exists = $this->db->exec(
            "SELECT COUNT(*) as count FROM task_label WHERE task_id = ? AND label_id = ?",
            [$this->id, $labelId]
        );

        if ($exists[0]['count'] == 0) {
            $this->db->exec(
                "INSERT INTO task_label (task_id, label_id) VALUES (?, ?)",
                [$this->id, $labelId]
            );
        }
    }

    /**
     * Remover una etiqueta de esta tarea
     * @param int $labelId ID de la etiqueta a remover
     * @return void
     */
    public function removeLabel(int $labelId): void
    {
        if (!$this->id) {
            return;
        }

        $this->db->exec(
            "DELETE FROM task_label WHERE task_id = ? AND label_id = ?",
            [$this->id, $labelId]
        );
    }


    /**
     * Relación: obtener el proyecto al que pertenece esta tarea
     * @return array<string, mixed>|null
     */
    public function projectArray(): ?array
    {
        if (!$this->project_id) {
            return null;
        }

        $result = $this->db->table('projects')
            ->where('id', '=', $this->project_id)
            ->first();

        return is_array($result) ? $result : null;
    }

    /**
     * Método de utilidad: verificar si la tarea está completada
     * @return bool
     */
    public function isCompleted(): bool
    {
        return (bool) $this->completed;
    }

    /**
     * Método de utilidad: verificar si la tarea está pendiente
     * @return bool
     */
    public function isPending(): bool
    {
        return !$this->isCompleted();
    }

    /**
     * Método de utilidad: obtener resumen de la tarea
     * @return string
     */
    public function getSummary(): string
    {
        $status = $this->isCompleted() ? 'Completada' : 'Pendiente';
        $description = $this->description ? substr($this->description, 0, 50) . '...' : 'Sin descripción';

        return "{$this->title} - {$status} - {$description}";
    }
}
