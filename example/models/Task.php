<?php

declare(strict_types=1);

namespace App\Models;

/**
 * Modelo Task
 * Gestiona tareas del sistema.
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
        'user_id',
    ];

    protected array $guarded = [];

    protected array $rules = [
        'title'      => ['required', 'min:3', 'max:200'],
        'project_id' => ['required'],
    ];

    /**
     * Estados disponibles para las tareas.
     */
    public const STATUS_TODO        = 'todo';
    public const STATUS_IN_PROGRESS = 'in_progress';
    public const STATUS_DONE        = 'done';

    /**
     * Prioridades disponibles.
     */
    public const PRIORITY_LOW    = 'low';
    public const PRIORITY_MEDIUM = 'medium';
    public const PRIORITY_HIGH   = 'high';
    public const PRIORITY_URGENT = 'urgent';

    /** Crear nueva tarea con defaults delegando validación a store(). */
    public static function create(array $attributes): static
    {
        $attributes['status']   = $attributes['status']   ?? self::STATUS_TODO;
        $attributes['priority'] = $attributes['priority'] ?? self::PRIORITY_MEDIUM;
        /** @var static $task */
        $task = static::dispense('tasks');
        $task->fill($attributes);
        $task->store();
        return $task;
    }

    /**
     * Obtener proyecto de la tarea.
     */
    public function project(): ?array
    {
        $project = Project::findOne('projects', (int)$this->project_id);
        return $project ? $project->export() : null;
    }

    /**
     * Obtener usuario asignado.
     */
    public function user(): ?array
    {
        if (!$this->user_id) {
            return null;
        }
        $user = User::findOne('users', (int)$this->user_id);
        return $user ? $user->export() : null;
    }

    /**
     * Obtener etiquetas de la tarea.
     */
    public function labels(): array
    {
        return static::orm()
            ->table('labels', Label::class)
            ->join('task_labels', 'labels.id', '=', 'task_labels.label_id')
            ->where('task_labels.task_id', '=', $this->id)
            ->orderBy('labels.created_at', 'DESC')
            ->select(['labels.*'])
            ->get();
    }

    /**
     * Obtener IDs de etiquetas de la tarea.
     */
    public function getLabelIds(): array
    {
        $rows = static::orm()
            ->table('task_labels')
            ->select(['label_id'])
            ->where('task_id', '=', $this->id)
            ->get();
        return array_column($rows, 'label_id');
    }

    /**
     * Asignar etiquetas a la tarea.
     */
    public function setLabels(array $labelIds): void
    {
        // Eliminar etiquetas actuales usando VersaModel
        $existingLabels = static::orm()
            ->table('task_labels')
            ->where('task_id', '=', $this->id)
            ->get();
        foreach ($existingLabels as $existing) {
            if (isset($existing['id'])) {
                $taskLabel = static::load('task_labels', (int)$existing['id']);
                if ($taskLabel) {
                    $taskLabel->trash();
                }
            }
        }

        // Asignar nuevas etiquetas usando VersaModel
        foreach ($labelIds as $labelId) {
            if (!empty($labelId)) {
                $taskLabel           = static::dispense('task_labels');
                $taskLabel->task_id  = $this->id;
                $taskLabel->label_id = $labelId;
                $taskLabel->store();
            }
        }
    }

    /**
     * Cambiar estado de la tarea.
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
     * Asignar usuario a la tarea.
     */
    public function assignUser(int $userId): void
    {
        $this->user_id = $userId;
        $this->store();
    }

    /**
     * Desasignar usuario de la tarea.
     */
    public function unassignUser(): void
    {
        $this->user_id = null;
        $this->store();
    }

    /**
     * Verificar si la tarea está vencida.
     */
    public function isOverdue(): bool
    {
        if (!$this->due_date) {
            return false;
        }

        return safe_strtotime($this->due_date) < time() && $this->status !== self::STATUS_DONE;
    }

    public function getUserIdByTaskId(int $taskId): ?int
    {
        $task = static::findOne('tasks', $taskId);
        return $task ? $task->user_id : null;
    }

    /**
     * Obtener clase CSS para prioridad.
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
     * Obtener clase CSS para estado.
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

    /**
     * Sobrescribir el método fill para manejar campos vacíos.
     */
    public function fill(array $attributes): self
    {
        // Normalizar campos opcionales
        $this->normalizeOptionalFields($attributes, ['user_id']);
        $this->normalizeOptionalDateFields($attributes, ['due_date']);

        // Procesar description vacía (convertir a null si está vacía para consistencia)
        if (isset($attributes['description']) && trim((string)$attributes['description']) === '') {
            $attributes['description'] = null;
        }

        // Llamar al método padre
        parent::fill($attributes);
        return $this;
    }

    /**
     * Definir tipos de propiedades para validación de esquema y tipado fuerte.
     */
    public static function definePropertyTypes(): array
    {
        return [
            'id'          => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'title'       => ['type' => 'string', 'max_length' => 200, 'nullable' => false],
            'description' => ['type' => 'text', 'nullable' => true],
            'status'      => [
                'type'     => 'enum',
                'values'   => ['todo', 'in_progress', 'done'],
                'nullable' => false,
                'default'  => 'todo'
            ],
            'priority' => [
                'type'     => 'enum',
                'values'   => ['low', 'medium', 'high', 'urgent'],
                'nullable' => false,
                'default'  => 'medium'
            ],
            'due_date'   => ['type' => 'date', 'nullable' => true],
            'project_id' => ['type' => 'int', 'nullable' => false],
            'user_id'    => ['type' => 'int', 'nullable' => true],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
            'updated_at' => ['type' => 'datetime', 'nullable' => false],
        ];
    }
}
