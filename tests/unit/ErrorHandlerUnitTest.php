<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\ErrorHandler;
use VersaORM\VersaORMException;

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
        // El handler recibe el array de datos del error, no un string. La versión
        // anterior lo interpolaba en un string y sólo afirmaba assertTrue(true), así
        // que no detectaba el error de tipo; además dejaba el handler instalado en el
        // estático de ErrorHandler y provocaba un warning de "Array to string
        // conversion" en los 25 tests siguientes.
        $received = [];
        ErrorHandler::setCustomHandler(static function (array $error) use (&$received): void {
            $received = $error;
        });

        try {
            ErrorHandler::handleException(new VersaORMException('fallo de prueba', 'TEST_CODE'));

            static::assertArrayHasKey('error', $received);
            static::assertSame('TEST_CODE', $received['error']['error_code']);
        } finally {
            // Imprescindible: es estado estático compartido por toda la suite.
            ErrorHandler::setCustomHandler(null);
        }
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
