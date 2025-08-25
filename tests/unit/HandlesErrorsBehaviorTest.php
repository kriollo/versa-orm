<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORMException;

require_once __DIR__ . '/../../vendor/autoload.php';

// Clase mínima que usa el trait para probar su comportamiento aislado
class MinimalModelForErrorHandling
{
    use \VersaORM\Traits\HandlesErrors;

    // Simular getTable y save/store/update/delete/find para pruebas mínimas
    public function getTable(): string
    {
        return 'minimal';
    }

    public function save()
    {
        // Simular excepción para comprobar withErrorHandling
        throw new VersaORMException('simulated', 'SIMULATED_ERROR');
    }

    public function store()
    {
        return true;
    }

    public function update(array $data)
    {
        return true;
    }

    public function delete()
    {
        return true;
    }

    public static function find($id)
    {
        return null;
    }

    // Wrappers públicos para pruebas que exponen comportamiento protegido
    public function _validateBeforeOperation(string $op): bool
    {
        return $this->validateBeforeOperation($op);
    }

    public function _handleModelErrorForTest(VersaORMException $e): mixed
    {
        return $this->handleModelError($e, []);
    }
}

class HandlesErrorsBehaviorTest extends TestCase
{
    public function testConfigureAndGetLastErrorInitial(): void
    {
        $m = new MinimalModelForErrorHandling();

        // No hay errores inicialmente
        self::assertFalse($m->hasError());
        self::assertNull($m->getLastError());

        // Configurar para no lanzar excepciones al manejar errores
        MinimalModelForErrorHandling::configureErrorHandling(['throw_on_error' => false, 'format_for_api' => false]);

        // Llamar safeSave que internamente lanzará y será manejado
        $res = $m->safeSave();

        // Como throw_on_error=false, safeSave debe retornar null y haber registrado lastError
        self::assertNull($res);
        self::assertTrue($m->hasError());
        self::assertIsArray($m->getLastError());
        self::assertArrayHasKey('error', $m->getLastError());
    }

    public function testValidateBeforeOperationEmptyAttributes(): void
    {
        $m = new MinimalModelForErrorHandling();

        // Atributos vacíos => validateBeforeOperation('save') debe fallar y retornar false
        $valid = $m->_validateBeforeOperation('save');

        self::assertFalse($valid);
        self::assertTrue($m->hasError());
        self::assertSame('EMPTY_ATTRIBUTES', $m->getLastErrorCode());
    }
}
