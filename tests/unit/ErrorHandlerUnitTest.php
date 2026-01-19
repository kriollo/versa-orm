<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\ErrorHandler;

/**
 * Tests para ErrorHandler - Manejo de errores del ORM.
 */
class ErrorHandlerUnitTest extends TestCase
{
    protected function setUp(): void
    {
        // Resetear el estado del ErrorHandler
        ErrorHandler::setDebugMode(false);
    }

    /**
     * Prueba setDebugMode y isDebugMode.
     */
    public function testSetAndIsDebugMode(): void
    {
        static::assertFalse(ErrorHandler::isDebugMode());

        ErrorHandler::setDebugMode(true);
        static::assertTrue(ErrorHandler::isDebugMode());

        ErrorHandler::setDebugMode(false);
        static::assertFalse(ErrorHandler::isDebugMode());
    }

    /**
     * Prueba setCustomHandler.
     */
    public function testSetCustomHandler(): void
    {
        $handler = static fn($error) => "custom: {$error}";

        ErrorHandler::setCustomHandler($handler);
        static::assertTrue(true); // Si llega aquí, no lanzó excepción
    }

    /**
     * Prueba configureFromVersaORM.
     */
    public function testConfigureFromVersaORM(): void
    {
        $config = [
            'debug' => true,
            'log_path' => '/tmp/logs',
        ];

        ErrorHandler::configureFromVersaORM($config);

        static::assertTrue(ErrorHandler::isConfigured());
        static::assertTrue(ErrorHandler::isDebugMode());
    }

    /**
     * Prueba getLogPath.
     */
    public function testGetLogPath(): void
    {
        $config = [
            'debug' => false,
            'log_path' => '/tmp/versaorm-test-logs',
        ];

        ErrorHandler::configureFromVersaORM($config);
        $logPath = ErrorHandler::getLogPath();

        static::assertIsString($logPath);
    }

    /**
     * Prueba isConfigured.
     */
    public function testIsConfigured(): void
    {
        // Configurar si no está configurado aún
        $config = ['debug' => true];
        ErrorHandler::configureFromVersaORM($config);

        static::assertTrue(ErrorHandler::isConfigured());
    }
}
