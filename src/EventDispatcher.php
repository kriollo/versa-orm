<?php

namespace VersaORM;

interface EventDispatcher
{
    /**
     * Registra un listener para un evento específico.
     *
     * @param string $event Nombre del evento (creating, created, etc)
     * @param callable $listener Closure o método a ejecutar
     */
    public function listen(string $event, callable $listener): void;

    /**
     * Dispara un evento y ejecuta todos los listeners registrados.
     *
     * @param string $event Nombre del evento
     * @param ModelEvent $context Contexto del modelo
     *
     * @return bool true si la operación puede continuar, false si se cancela
     */
    public function dispatch(string $event, ModelEvent $context): bool;
}
