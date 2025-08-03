<?php

namespace App\Models;

/**
 * Modelo Task
 * Gestiona tareas del sistema
 */
class Task extends BaseModel
{
    protected string $table = 'tasks';

    protected array $fillable = [
        'title',
        'description',
        'status',
        'priority',
        'due_date',
        'project_id',
        'user_id'
    ];

    protected array $guarded = [];

    protected array $rules = [
        'title' => ['required', 'min:3', 'max:200'],
        'project_id' => ['required']
    ];

    /**
     * Estados disponibles para las tareas
     */
    const STATUS_TODO = 'todo';
    const STATUS_IN_PROGRESS = 'in_progress';
    const STATUS_DONE = 'done';

    /**
     * Prioridades disponibles
     */
    const PRIORITY_LOW = 'low';
    const PRIORITY_MEDIUM = 'medium';
    const PRIORITY_HIGH = 'high';
    const PRIORITY_URGENT = 'urgent';

    /**
     * Buscar por ID
     */
    public static function find(int $id): ?self
    {
        return static::findOne('tasks', $id);
    }

    /**
     * Obtener todas las tareas
     */
    public static function all(): array
    {
        return static::findAll('tasks');
    }

    /**
     * Crear nueva tarea
     */
    public static function create(array $attributes): static
    {
        // Aplicar valores por defecto
        if (!isset($attributes['status'])) {
            $attributes['status'] = self::STATUS_TODO;
        }
        if (!isset($attributes['priority'])) {
            $attributes['priority'] = self::PRIORITY_MEDIUM;
        }

        // Validar antes de crear
        $errors = [];
        if (empty($attributes['title'])) $errors[] = 'El título es requerido';
        if (empty($attributes['project_id'])) $errors[] = 'El proyecto es requerido';

        if (!empty($errors)) {
            throw new \Exception('Errores de validación: ' . implode(', ', $errors));
        }

        // Crear instancia correctamente con el nombre de tabla
        $ormInstance = static::getGlobalORM();
        if (!$ormInstance) {
            throw new \Exception('No ORM instance available. Call Model::setORM() first.');
        }
        $task = new static('tasks', $ormInstance);
        $task->fill($attributes);
        $task->store();
        return $task;
    }

    /**
     * Obtener proyecto de la tarea
     */
    public function project(): ?array
    {
        $result = static::getAll("SELECT * FROM projects WHERE id = ?", [$this->project_id]);
        return $result ? $result[0] : null;
    }

    /**
     * Obtener usuario asignado
     */
    public function user(): ?array
    {
        if (!$this->user_id) return null;
        $result = static::getAll("SELECT * FROM users WHERE id = ?", [$this->user_id]);
        return $result ? $result[0] : null;
    }

    /**
     * Obtener etiquetas de la tarea
     */
    public function labels(): array
    {
        return static::getAll(
            "SELECT l.* FROM labels l
             INNER JOIN task_labels tl ON l.id = tl.label_id
             WHERE tl.task_id = ?",
            [$this->id]
        );
    }

    /**
     * Obtener IDs de etiquetas de la tarea
     */
    public function getLabelIds(): array
    {
        $results = static::getAll(
            "SELECT label_id FROM task_labels WHERE task_id = ?",
            [$this->id]
        );
        return array_column($results, 'label_id');
    }

    /**
     * Asignar etiquetas a la tarea
     */
    public function setLabels(array $labelIds): void
    {
        // Eliminar etiquetas actuales
        static::execSql("DELETE FROM task_labels WHERE task_id = ?", [$this->id]);

        // Asignar nuevas etiquetas
        foreach ($labelIds as $labelId) {
            if (!empty($labelId)) {
                static::execSql(
                    "INSERT INTO task_labels (task_id, label_id) VALUES (?, ?)",
                    [$this->id, $labelId]
                );
            }
        }
    }

    /**
     * Cambiar estado de la tarea
     */
    public function changeStatus(string $status): void
    {
        $validStatuses = [self::STATUS_TODO, self::STATUS_IN_PROGRESS, self::STATUS_DONE];
        if (!in_array($status, $validStatuses)) {
            throw new \Exception('Estado inválido');
        }

        $this->status = $status;
        $this->store();
    }

    /**
     * Asignar usuario a la tarea
     */
    public function assignUser(int $userId): void
    {
        $this->user_id = $userId;
        $this->store();
    }

    /**
     * Desasignar usuario de la tarea
     */
    public function unassignUser(): void
    {
        $this->user_id = null;
        $this->store();
    }

    /**
     * Verificar si la tarea está vencida
     */
    public function isOverdue(): bool
    {
        if (!$this->due_date) return false;
        return strtotime($this->due_date) < time() && $this->status !== self::STATUS_DONE;
    }

    /**
     * Obtener clase CSS para prioridad
     */
    public function getPriorityClass(): string
    {
        switch ($this->priority) {
            case self::PRIORITY_URGENT:
                return 'bg-red-100 text-red-800 border-red-200';
            case self::PRIORITY_HIGH:
                return 'bg-orange-100 text-orange-800 border-orange-200';
            case self::PRIORITY_MEDIUM:
                return 'bg-yellow-100 text-yellow-800 border-yellow-200';
            case self::PRIORITY_LOW:
                return 'bg-green-100 text-green-800 border-green-200';
            default:
                return 'bg-gray-100 text-gray-800 border-gray-200';
        }
    }

    /**
     * Obtener clase CSS para estado
     */
    public function getStatusClass(): string
    {
        switch ($this->status) {
            case self::STATUS_TODO:
                return 'bg-gray-100 text-gray-800';
            case self::STATUS_IN_PROGRESS:
                return 'bg-blue-100 text-blue-800';
            case self::STATUS_DONE:
                return 'bg-green-100 text-green-800';
            default:
                return 'bg-gray-100 text-gray-800';
        }
    }
}
