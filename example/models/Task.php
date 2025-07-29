<?php

namespace Example\Models;

use VersaORM\Traits\VersaORMTrait;

class Task
{
    use VersaORMTrait;
    public $table = 'tasks';
    public $id;
    public $title;
    public $description;
    public $completed;
    public $created_at;
    public $updated_at;

    public function __construct()
    {
        $this->connectORM();
    }

    public function __destruct()
    {
        $this->disconnectORM();
    }

    // Crear nueva tarea
    public function create($data)
    {
        $task = $this->db->table($this->table)->dispense();
        $task->title = $data['title'];
        $task->description = $data['description'] ?? '';
        $task->completed = $data['completed'] ?? false;
        $task->store();
        return $task;
    }

    // Obtener todas las tareas
    public static function all()
    {
        $instance = new self();
        return $instance->db->table($instance->table)->orderBy('id', 'desc')->findAll();
    }

    // Exportar todas las tareas como array
    public static function allExported()
    {
        $tasks = self::all();
        return \VersaORM\Model::exportAll($tasks);
    }

    // Permitir acceso público a los atributos para la API
    public function getAttributes(): array
    {
        $props = array('id', 'title', 'description', 'completed', 'created_at', 'updated_at');
        $out = array();
        foreach ($props as $prop) {
            $out[$prop] = isset($this->$prop) ? $this->$prop : null;
        }
        return $out;
    }

    // Buscar por ID
    public function find($id)
    {
        return $this->db->table($this->table)->find($id);
    }

    // Actualizar tarea
    public function update($id, $data)
    {
        $task = $this->find($id);
        if ($task) {
            foreach ($data as $k => $v) {
                $task->$k = $v;
            }
            $task->store();
        }
        return $task;
    }

    // Eliminar tarea
    public function delete($id)
    {
        $task = $this->find($id);
        if ($task) {
            $task->trash();
            return true;
        }
        return false;
    }
}
