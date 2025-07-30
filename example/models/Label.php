<?php

namespace Example\Models;

/**
 * Modelo Label - Etiquetas para tareas (estilo Gmail)
 *
 * Campos de la tabla 'labels':
 * - id: int (PK, auto_increment)
 * - name: string (required, único)
 * - color: string (opcional)
 * - created_at: timestamp
 * - updated_at: timestamp
 */
class Label extends BaseModel
{
    protected string $table = 'labels';
    protected array $fillable = [
        'name',
        'color'
    ];

    /**
     * Relación: una etiqueta tiene muchas tareas (muchos a muchos)
     * @return array<int, array<string, mixed>>
     */
    public function tasksArray(): array
    {
        $sql = "SELECT t.* FROM tasks t JOIN task_label tl ON tl.task_id = t.id WHERE tl.label_id = ?";
        return $this->db->exec($sql, [$this->id]);
    }
}
