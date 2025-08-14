<?php

declare(strict_types=1);

namespace VersaORM;

use Exception;

/**
 * Excepción personalizada para VersaORM que incluye información de consulta.
 */
class VersaORMException extends Exception
{
    /** @var float Momento de creación (monotónico aproximado) */
    private float $raisedAt;

    /** @var string|null Nombre del método público/QueryBuilder que originó el error */
    private ?string $originMethod = null;

    /** @var string|null Driver de base de datos activo */
    private ?string $driver = null;

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
        $this->raisedAt = microtime(true);
        parent::__construct($message, $code, $previous);
    }

    /** Representación legible para debugging rápido */
    public function __toString(): string
    {
        return sprintf(
            '[%s/%s] %s | driver=%s origin=%s query=%s bindings=%s',
            $this->errorCode,
            $this->sqlState ?? '-',
            $this->getMessage(),
            $this->driver ?? 'n/a',
            $this->originMethod ?? 'n/a',
            ($this->query !== null && $this->query !== '') ? substr($this->query, 0, 200) : 'n/a',
            json_encode($this->bindings),
        );
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

    /** Define el método origen (fluente). */
    public function withOrigin(?string $method): self
    {
        $this->originMethod = $method;

        return $this;
    }

    /** Define el driver DB que estaba activo. */
    public function withDriver(?string $driver): self
    {
        $this->driver = $driver;

        return $this;
    }

    /** Actualiza/mezcla detalles adicionales (no sobreescribe existentes). */
    /**
     * @param array<string,mixed> $extra
     */
    public function augmentDetails(array $extra): self
    {
        $this->errorDetails = $extra + $this->errorDetails;

        return $this;
    }

    /** Devuelve el método origen si se estableció. */
    public function getOriginMethod(): ?string
    {
        return $this->originMethod;
    }

    /** Devuelve driver DB. */
    public function getDriver(): ?string
    {
        return $this->driver;
    }

    /** Marca de tiempo (epoch flotante) de la excepción. */
    public function getRaisedAt(): float
    {
        return $this->raisedAt;
    }

    /** Serialización enriquecida para logging. */
    /**
     * @return array<string,mixed>
     */
    public function toLogArray(): array
    {
        /** @var Exception|null $prev */
        $prev = $this->getPrevious();

        return [
            'timestamp' => date('c'),
            'raised_at' => $this->raisedAt,
            'class' => static::class,
            'message' => $this->getMessage(),
            'error_code' => $this->errorCode,
            'sql_state' => $this->sqlState,
            'origin_method' => $this->originMethod,
            'driver' => $this->driver,
            'query' => $this->query,
            'bindings' => $this->bindings,
            'details' => $this->errorDetails,
            'previous' => $prev instanceof Exception ? [
                'class' => get_class($prev),
                'message' => $prev->getMessage(),
                'code' => $prev->getCode(),
            ] : null,
            'trace' => $this->simplifiedTrace(),
        ];
    }

    /** Traza simplificada (sin argumentos largos) */
    /**
     * @return array<int,array<string,int|string|null>>
     */
    private function simplifiedTrace(): array
    {
        $out = [];
        foreach ($this->getTrace() as $i => $frame) {
            $out[] = [
                'i' => $i,
                'file' => $frame['file'] ?? null,
                'line' => $frame['line'] ?? null,
                'function' => $frame['function'] ?? null,
                'class' => $frame['class'] ?? null,
                'type' => $frame['type'] ?? null,
            ];
        }

        return $out;
    }
}
