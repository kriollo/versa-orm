<?php

declare(strict_types=1);

namespace VersaORM;

class ModelEvent
{
    /** @var object Instancia del modelo */
    public $model;

    /** @var array<string, mixed> Datos originales antes del cambio */
    public array $original = [];

    /** @var array<string, mixed> Cambios realizados */
    public array $changes = [];

    /** @var bool Permite cancelar la operación */
    public bool $cancel = false;

    /** @var string|null Mensaje de error opcional */
    public ?string $error = null;

    /**
     * @param object $model
     * @param array<string, mixed> $original
     * @param array<string, mixed> $changes
     */
    public function __construct($model, array $original = [], array $changes = [])
    {
        $this->model = $model;
        $this->original = $original;
        $this->changes = $changes;
    }

    /**
     * Cancela la operación y opcionalmente define un mensaje de error.
     */
    public function cancel(?string $error = null): void
    {
        $this->cancel = true;
        $this->error = $error;
    }
}
