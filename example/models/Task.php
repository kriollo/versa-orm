<?php

declare(strict_types=1);

namespace App\Models;

use App\BaseModel;
use Exception;
use VersaORM\Relations\BelongsTo;
use VersaORM\Relations\BelongsToMany;
use VersaORM\VersaModel;

use function in_array;

/**
 * Modelo Task
 * Gestiona tareas del sistema.
 */
class Task extends BaseModel
{
    /**
     * Estados disponibles para las tareas.
     */
    public const STATUS_TODO = 'todo';
    public const STATUS_IN_PROGRESS = 'in_progress';
    public const STATUS_DONE = 'done';

    /**
     * Prioridades disponibles.
     */
    public const PRIORITY_LOW = 'low';
    public const PRIORITY_MEDIUM = 'medium';
    public const PRIORITY_HIGH = 'high';
    public const PRIORITY_URGENT = 'urgent';

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
        'title' => ['required', 'min:3', 'max:200'],
        'project_id' => ['required'],
    ];

    /** Obtener el conteo total de tareas. */
    public static function countAll(): int
    {
        return self::queryTable()->count();
    }

    /** Obtener el conteo de tareas pendientes. */
    public static function countPending(): int
    {
        return models()->task()->getOrm()->table('tasks')->where('status', '=', self::STATUS_TODO)->count();
    }

    /** Obtener las tareas recientes con información relacionada. */
    public static function getRecent(int $limit = 5): array
    {
        return self::queryTable()
            ->lazy()
            ->with(['project', 'user', 'labels'])
            ->orderBy('created_at', 'desc')
            ->limit($limit)
            ->collect();
    }

    /** Relación N:M: etiquetas de la tarea (BelongsToMany). */
    public function labelsRelation(): \VersaORM\Relations\BelongsToMany
    {
        return $this->belongsToMany(
            Label::class,
            'task_labels',
            'task_id',
            'label_id',
            'id',
            'id',
        );
    }

    /** Adjuntar etiqueta a la tarea. */
    public function attachLabel(int $labelId): void
    {
        $this->labelsRelation()->attach($labelId);
    }

    /** Separar etiqueta de la tarea. */
    public function detachLabel(int $labelId): void
    {
        $this->labelsRelation()->detach($labelId);
    }

    /** Sincronizar etiquetas de la tarea. */
    public function syncLabels(array $labelIds): array
    {
        return $this->labelsRelation()->sync($labelIds);
    }

    /** Recargar la tarea desde la base de datos (fresh). */
    public function fresh(string $primaryKey = 'id'): static
    {
        return parent::fresh($primaryKey);
    }

    /** Crear nueva tarea con defaults delegando validación a store(). */
    public function createOne(array $attributes): self
    {
        $attributes['status'] ??= self::STATUS_TODO;
        $attributes['priority'] ??= self::PRIORITY_MEDIUM;
        $this->fill($attributes);
        $this->store();

        return $this;
    }

    /**
     * Obtener proyecto de la tarea.
     */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class, 'id', 'project_id');
    }

    /**
     * Obtener usuario asignado.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id');
    }

    /**
     * Obtener etiquetas de la tarea.
     */
    public function labels(): BelongsToMany
    {
        return $this->belongsToMany(Label::class, 'task_labels', 'task_id', 'label_id');
    }

    /**
     * Obtener IDs de etiquetas de la tarea.
     */
    public function getLabelIds(): array
    {
        $rows = $this->getOrm()
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
        $existingLabels = $this->getOrm()
            ->table('task_labels')
            ->where('task_id', '=', $this->id)
            ->get();

        foreach ($existingLabels as $existing) {
            if (isset($existing['id'])) {
                $taskLabel = $this->load('task_labels', (int) $existing['id']);

                if ($taskLabel instanceof VersaModel) {
                    $taskLabel->trash();
                }
            }
        }

        // Asignar nuevas etiquetas usando VersaModel
        foreach ($labelIds as $labelId) {
            if (!empty($labelId)) {
                $taskLabel = $this->dispenseInstance('task_labels');
                $taskLabel->task_id = $this->id;
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

        if (!in_array($status, $validStatuses, true)) {
            throw new Exception('Estado inválido');
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
        $task = $this->getOrm()->table('tasks', self::class)->where('id', '=', $taskId)->findOne();

        return $task ? $task->user_id : null;
    }

    /**
     * Obtener clase CSS para prioridad.
     */
    public function getPriorityClass(): string
    {
        return match ($this->priority) {
            self::PRIORITY_URGENT => 'bg-red-100 text-red-800 border-red-200',
            self::PRIORITY_HIGH => 'bg-orange-100 text-orange-800 border-orange-200',
            self::PRIORITY_MEDIUM => 'bg-yellow-100 text-yellow-800 border-yellow-200',
            self::PRIORITY_LOW => 'bg-green-100 text-green-800 border-green-200',
            default => 'bg-gray-100 text-gray-800 border-gray-200',
        };
    }

    /**
     * Obtener clase CSS para estado.
     */
    public function getStatusClass(): string
    {
        return match ($this->status) {
            self::STATUS_TODO => 'bg-gray-100 text-gray-800',
            self::STATUS_IN_PROGRESS => 'bg-blue-100 text-blue-800',
            self::STATUS_DONE => 'bg-green-100 text-green-800',
            default => 'bg-gray-100 text-gray-800',
        };
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
        if (isset($attributes['description']) && trim((string) $attributes['description']) === '') {
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
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'title' => ['type' => 'string', 'max_length' => 200, 'nullable' => false],
            'description' => ['type' => 'text', 'nullable' => true],
            'status' => [
                'type' => 'enum',
                'values' => ['todo', 'in_progress', 'done'],
                'nullable' => false,
                'default' => 'todo',
            ],
            'priority' => [
                'type' => 'enum',
                'values' => ['low', 'medium', 'high', 'urgent'],
                'nullable' => false,
                'default' => 'medium',
            ],
            'due_date' => ['type' => 'date', 'nullable' => true],
            'project_id' => ['type' => 'int', 'nullable' => false],
            'user_id' => ['type' => 'int', 'nullable' => true],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
            'updated_at' => ['type' => 'datetime', 'nullable' => false],
        ];
    }
}
