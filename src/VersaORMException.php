<?php

declare(strict_types=1);

namespace VersaORM;

use Exception;

/**
 * Excepción personalizada para VersaORM que incluye información de consulta.
 */
class VersaORMException extends Exception
{
    private $query;
    private $bindings;
    private $errorCode;
    private $errorDetails;
    private $sqlState;

    public function __construct(
        string $message,
        string $errorCode = 'UNKNOWN_ERROR',
        ?string $query = null,
        array $bindings = [],
        array $errorDetails = [],
        ?string $sqlState = null,
        int $code = 0,
        Exception $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->errorCode = $errorCode;
        $this->query = $query;
        $this->bindings = $bindings;
        $this->errorDetails = $errorDetails;
        $this->sqlState = $sqlState;
    }

    /**
     * Obtiene la consulta SQL que causó el error.
     *
     * @return string|null
     */
    public function getQuery(): ?string
    {
        return $this->query;
    }

    /**
     * Obtiene los parámetros de la consulta SQL.
     *
     * @return array
     */
    public function getBindings(): array
    {
        return $this->bindings;
    }

    /**
     * Obtiene el código de error específico de VersaORM.
     *
     * @return string
     */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    /**
     * Obtiene los detalles adicionales del error.
     *
     * @return array
     */
    public function getErrorDetails(): array
    {
        return $this->errorDetails;
    }

    /**
     * Obtiene el estado SQL si está disponible.
     *
     * @return string|null
     */
    public function getSqlState(): ?string
    {
        return $this->sqlState;
    }
}
