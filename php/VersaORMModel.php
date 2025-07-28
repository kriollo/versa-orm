<?php

declare(strict_types=1);

class VersaORMModel
{
    private string $table;
    private array $config;
    private array $attributes = [];

    public function __construct(string $table, array $config)
    {
        $this->table = $table;
        $this->config = $config;
    }

    /**
     * Cargar los datos del modelo desde la base de datos.
     *
     * @param mixed $id
     * @param string $pk
     * @return self
     */
    public function load($id, string $pk = 'id'): self
    {
        $data = VersaORM::table($this->table)->where($pk, '=', $id)->first();
        if ($data) {
            $this->attributes = $data;
        } else {
            throw new Exception("Record not found");
        }
        return $this;
    }

    /**
     * Guardar el modelo en la base de datos.
     *
     * @return bool
     */
    public function store(): bool
    {
        if (isset($this->attributes['id'])) {
            return VersaORM::table($this->table)->where('id', '=', $this->attributes['id'])->update($this->attributes);
        } else {
            $id = VersaORM::table($this->table)->insertGetId($this->attributes);
            $this->attributes['id'] = $id;
            return true;
        }
    }

    /**
     * Eliminar el registro del modelo en la base de datos.
     *
     * @return bool
     */
    public function trash(): bool
    {
        if (!isset($this->attributes['id'])) {
            throw new Exception("Cannot delete without an ID");
        }
        return VersaORM::table($this->table)->where('id', '=', $this->attributes['id'])->delete();
    }

    /**
     * Asignar valor a un atributo.
     *
     * @param string $key
     * @param mixed $value
     */
    public function __set(string $key, $value)
    {
        $this->attributes[$key] = $value;
    }

    /**
     * Obtener el valor de un atributo.
     *
     * @param string $key
     * @return mixed
     */
    public function __get(string $key)
    {
        return $this->attributes[$key] ?? null;
    }

    /**
     * Convertir el modelo a un array.
     *
     * @return array
     */
    public function toArray(): array
    {
        return $this->attributes;
    }
}
