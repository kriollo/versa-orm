<?php

namespace Example\Models;

/**
 * Modelo pivote para la relación muchos a muchos entre tareas y etiquetas
 *
 * Tabla: task_label
 * - id: int (PK, auto_increment)
 * - task_id: int (FK)
 * - label_id: int (FK)
 */
class TaskLabel extends BaseModel
{
    protected string $table = 'task_label';
    protected array $fillable = [
        'task_id',
        'label_id'
    ];
}
