<?php

declare(strict_types=1);

namespace VersaORM;

use Exception;

/**
 * Excepción personalizada para VersaORM que incluye información de consulta.
 */
class VersaORMException extends Exception
{
    /**
     * @param array<int, mixed> $bindings
     * @param array<string, mixed> $errorDetails
     */
    public function __construct(
        string $message,
        private string $errorCode = 'UNKNOWN_ERROR',
        private ?string $query = null,
        private array $bindings = [],
        private array $errorDetails = [],
        private ?string $sqlState = null,
        int $code = 0,
        ?Exception $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Obtiene la consulta SQL que causó el error.
     */
    public function getQuery(): ?string
    {
        return $this->query;
    }

    /**
     * Obtiene los parámetros de la consulta SQL.
     *
     * @return array<int, mixed>
     */
    public function getBindings(): array
    {
        return $this->bindings;
    }

    /**
     * Obtiene el código de error específico de VersaORM.
     */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    /**
     * Obtiene el detalle de error.
     *
     * @return array<string, mixed>
     */
    public function getErrorDetails(): array
    {
        return $this->errorDetails;
    }

    /**
     * Obtiene el estado SQL si está disponible.
     */
    public function getSqlState(): ?string
    {
        return $this->sqlState;
    }
}
