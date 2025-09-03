<?php

declare(strict_types=1);

namespace App;

use VersaORM\VersaModel;
use VersaORM\VersaORM;

class App
{
    private null|VersaORM $orm = null;

    private null|ModelManager $models = null;

    public function __construct(
        private Request $request,
        private array $config,
    ) {
    }

    public function request(): Request
    {
        return $this->request;
    }

    public function orm(): VersaORM
    {
        if (!$this->orm instanceof VersaORM) {
            // Construcción perezosa: crear ORM hasta el primer uso
            $this->orm = OrmFactory::make($this->config, $this->request);
            // Registrar global para compatibilidad interna (QueryBuilder que no recibe explícito)
            VersaModel::setORM($this->orm);
        }

        return $this->orm;
    }

    public function models(): ModelManager
    {
        if (!$this->models instanceof ModelManager) {
            // Entregar el ORM perezosamente al manager
            $this->models = new ModelManager($this->orm());
        }

        return $this->models;
    }
}
