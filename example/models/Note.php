<?php

declare(strict_types=1);

namespace App\Models;

/**
 * Modelo Note
 * Gestiona notas de las tareas.
 */
class Note extends BaseModel
{
    protected string $table = 'task_notes';

    protected array $fillable = [
        'content',
        'task_id',
        'user_id',
    ];

    protected array $guarded = [];

    protected array $rules = [
        'content' => ['required', 'min:3'],
        'task_id' => ['required'],
        'user_id' => ['required'],
    ];

    // Buscar por ID se hace vía instancia heredada de BaseModel: (new Note(...))->find($id)

    /** Listar notas por task_id como arrays exportados (instancia). */
    public function findByTask(int $taskId): array
    {
        return $this->getOrm()
            ->table('task_notes', static::class)
            ->where('task_id', '=', $taskId)
            ->orderBy('created_at', 'DESC')
            ->get()
        ;
    }

    /** Crear nueva nota usando strong typing (instancia). */
    public function createOne(array $attributes): self
    {
        $this->fill($attributes);
        $this->store();

        return $this;
    }

    /**
     * Obtener tarea de la nota.
     */
    public function task(): ?array
    {
        $task = $this->getOrm()->table('tasks', Task::class)->where('id', '=', (int) $this->task_id)->findOne();

        return $task ? $task->export() : null;
    }

    /**
     * Obtener usuario que creó la nota.
     */
    public function user(): ?array
    {
        $user = $this->getOrm()->table('users', User::class)->where('id', '=', (int) $this->user_id)->findOne();

        return $user ? $user->export() : null;
    }

    /**
     * Definir tipos de propiedades para validación de esquema y tipado fuerte.
     */
    public static function definePropertyTypes(): array
    {
        return [
            'id'         => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'content'    => ['type' => 'text', 'nullable' => false],
            'task_id'    => ['type' => 'int', 'nullable' => false],
            'user_id'    => ['type' => 'int', 'nullable' => false],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
            'updated_at' => ['type' => 'datetime', 'nullable' => false],
        ];
    }
}
