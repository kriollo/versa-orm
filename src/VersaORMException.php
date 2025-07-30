<?php

declare(strict_types=1);

namespace VersaORM;

use Exception;

/**
 * Excepción personalizada para VersaORM que incluye información de consulta.
 */
class VersaORMException extends Exception
{
    private ?string $query;
    /** @var array<int, mixed> */
    private array $bindings;
    private string $errorCode;
    /** @var array<string, mixed> */
    private array $errorDetails;
    private ?string $sqlState;

    /**
     * @param string $message
     * @param string $errorCode
     * @param string|null $query
     * @param array<int, mixed> $bindings
     * @param array<string, mixed> $errorDetails
     * @param string|null $sqlState
     * @param int $code
     * @param Exception|null $previous
     */
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
     * @return array<int, mixed>
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
     *
     * @return string|null
     */
    public function getSqlState(): ?string
    {
        return $this->sqlState;
    }
}
