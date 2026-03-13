<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use Exception;
use PHPUnit\Framework\TestCase;
use VersaORM\VersaORMException;

/**
 * Tests comprehensivos para VersaORMException
 * Target: 73.24% → 95%+
 */
class VersaORMExceptionComprehensiveTest extends TestCase
{
    /** Test: Constructor con todos los parámetros */
    public function testConstructorWithAllParameters(): void
    {
        $exception = new VersaORMException(
            'Test error message',
            'TEST_ERROR',
            'SELECT * FROM users WHERE id = ?',
            [1],
            ['detail' => 'Some detail'],
            '23000',
            500,
            new Exception('Previous exception'),
        );

        static::assertSame('Test error message', $exception->getMessage());
        static::assertSame('TEST_ERROR', $exception->getErrorCode());
        static::assertSame('SELECT * FROM users WHERE id = ?', $exception->getQuery());
        static::assertEquals([1], $exception->getBindings());
        static::assertEquals(['detail' => 'Some detail'], $exception->getErrorDetails());
        static::assertSame('23000', $exception->getSqlState());
        static::assertSame(500, $exception->getCode());
        static::assertInstanceOf(Exception::class, $exception->getPrevious());
    }

    /** Test: Constructor con parámetros mínimos */
    public function testConstructorWithMinimalParameters(): void
    {
        $exception = new VersaORMException('Simple error');

        static::assertSame('Simple error', $exception->getMessage());
        static::assertSame('UNKNOWN_ERROR', $exception->getErrorCode());
        static::assertNull($exception->getQuery());
        static::assertEquals([], $exception->getBindings());
        static::assertEquals([], $exception->getErrorDetails());
        static::assertNull($exception->getSqlState());
    }

    /** Test: getQuery retorna la consulta SQL */
    public function testGetQueryReturnsQuery(): void
    {
        $exception = new VersaORMException(
            'Query error',
            'SQL_ERROR',
            'UPDATE users SET name = ? WHERE id = ?',
            ['John', 1],
        );

        static::assertSame('UPDATE users SET name = ? WHERE id = ?', $exception->getQuery());
    }

    /** Test: getQuery retorna null cuando no hay query */
    public function testGetQueryReturnsNullWhenNoQuery(): void
    {
        $exception = new VersaORMException('Error without query');

        static::assertNull($exception->getQuery());
    }

    /** Test: getBindings retorna los parámetros */
    public function testGetBindingsReturnsBindings(): void
    {
        $bindings = [1, 'test@example.com', true];
        $exception = new VersaORMException(
            'Binding error',
            'BIND_ERROR',
            'SELECT * FROM users WHERE id = ? AND email = ? AND active = ?',
            $bindings,
        );

        static::assertEquals($bindings, $exception->getBindings());
    }

    /** Test: getBindings retorna array vacío cuando no hay bindings */
    public function testGetBindingsReturnsEmptyArrayWhenNoBindings(): void
    {
        $exception = new VersaORMException('No bindings');

        static::assertEquals([], $exception->getBindings());
    }

    /** Test: getErrorCode retorna código de error */
    public function testGetErrorCodeReturnsErrorCode(): void
    {
        $exception = new VersaORMException('Custom error', 'CUSTOM_CODE_123');

        static::assertSame('CUSTOM_CODE_123', $exception->getErrorCode());
    }

    /** Test: getErrorCode retorna UNKNOWN_ERROR por defecto */
    public function testGetErrorCodeReturnsUnknownErrorByDefault(): void
    {
        $exception = new VersaORMException('Default error');

        static::assertSame('UNKNOWN_ERROR', $exception->getErrorCode());
    }

    /** Test: getErrorDetails retorna detalles de error */
    public function testGetErrorDetailsReturnsDetails(): void
    {
        $details = [
            'table' => 'users',
            'column' => 'email',
            'constraint' => 'unique_email',
            'driver_code' => 1062,
        ];

        $exception = new VersaORMException('Constraint error', 'CONSTRAINT_VIOLATION', null, [], $details);

        static::assertEquals($details, $exception->getErrorDetails());
    }

    /** Test: getErrorDetails retorna array vacío cuando no hay detalles */
    public function testGetErrorDetailsReturnsEmptyArrayWhenNoDetails(): void
    {
        $exception = new VersaORMException('No details');

        static::assertEquals([], $exception->getErrorDetails());
    }

    /** Test: getSqlState retorna estado SQL */
    public function testGetSqlStateReturnsSqlState(): void
    {
        $exception = new VersaORMException('SQL state error', 'SQL_ERROR', null, [], [], '23000'); // Integrity constraint violation

        static::assertSame('23000', $exception->getSqlState());
    }

    /** Test: getSqlState retorna null cuando no hay SQL state */
    public function testGetSqlStateReturnsNullWhenNoSqlState(): void
    {
        $exception = new VersaORMException('No SQL state');

        static::assertNull($exception->getSqlState());
    }

    /** Test: __toString incluye toda la información relevante */
    public function testToStringIncludesAllRelevantInfo(): void
    {
        $exception = new VersaORMException(
            'Complex error',
            'COMPLEX_ERROR',
            'SELECT * FROM users WHERE id = ?',
            [123],
            ['detail' => 'Test detail'],
            '42000',
        );

        // Configurar driver y origin method
        $exception->withDriver('mysql');
        $exception->withOrigin('QueryBuilder::get');

        $string = (string) $exception;

        // Verificar que contiene información clave
        static::assertStringContainsString('COMPLEX_ERROR', $string);
        static::assertStringContainsString('42000', $string);
        static::assertStringContainsString('Complex error', $string);
        static::assertStringContainsString('mysql', $string);
        static::assertStringContainsString('QueryBuilder::get', $string);
        static::assertStringContainsString('SELECT * FROM users', $string);
        static::assertStringContainsString('[123]', $string);
    }

    /** Test: __toString con query null muestra 'n/a' */
    public function testToStringWithNullQueryShowsNA(): void
    {
        $exception = new VersaORMException('Error without query');

        $string = (string) $exception;

        static::assertStringContainsString('query=n/a', $string);
    }

    /** Test: __toString con query vacía muestra 'n/a' */
    public function testToStringWithEmptyQueryShowsNA(): void
    {
        $exception = new VersaORMException('Error with empty query', 'ERROR', ''); // Query vacía

        $string = (string) $exception;

        static::assertStringContainsString('query=n/a', $string);
    }

    /** Test: __toString trunca queries largas */
    public function testToStringTruncatesLongQueries(): void
    {
        $longQuery = str_repeat('SELECT * FROM users WHERE id = ? AND ', 20);
        $exception = new VersaORMException('Long query error', 'LONG_QUERY', $longQuery);

        $string = (string) $exception;

        // Debe truncar a 200 caracteres
        static::assertLessThanOrEqual(
            400, // Más espacio para el resto del mensaje
            strlen($string),
        );
    }

    /** Test: __toString sin driver muestra 'n/a' */
    public function testToStringWithoutDriverShowsNA(): void
    {
        $exception = new VersaORMException('No driver error');

        $string = (string) $exception;

        static::assertStringContainsString('driver=n/a', $string);
    }

    /** Test: __toString sin origin method muestra 'n/a' */
    public function testToStringWithoutOriginMethodShowsNA(): void
    {
        $exception = new VersaORMException('No origin error');

        $string = (string) $exception;

        static::assertStringContainsString('origin=n/a', $string);
    }

    /** Test: __toString sin SQL state muestra '-' */
    public function testToStringWithoutSqlStateShowsDash(): void
    {
        $exception = new VersaORMException('No SQL state');

        $string = (string) $exception;

        // Formato: [ERROR_CODE/-]
        static::assertStringContainsString('/-]', $string);
    }

    /** Test: withDriver establece el driver */
    public function testWithDriverSetsDriver(): void
    {
        $exception = new VersaORMException('Test');
        $exception->withDriver('postgresql');

        $string = (string) $exception;
        static::assertStringContainsString('driver=postgresql', $string);
    }

    /** Test: withOrigin establece el método origen */
    public function testWithOriginSetsOriginMethod(): void
    {
        $exception = new VersaORMException('Test');
        $exception->withOrigin('VersaModel::store');

        $string = (string) $exception;
        static::assertStringContainsString('origin=VersaModel::store', $string);
    }

    /** Test: getRaisedAt retorna timestamp */
    public function testGetRaisedAtReturnsTimestamp(): void
    {
        $before = microtime(true);
        $exception = new VersaORMException('Timing test');
        $after = microtime(true);

        $raisedAt = $exception->getRaisedAt();

        static::assertGreaterThanOrEqual($before, $raisedAt);
        static::assertLessThanOrEqual($after, $raisedAt);
    }

    /** Test: getDriver retorna driver configurado */
    public function testGetDriverReturnsDriver(): void
    {
        $exception = new VersaORMException('Driver test');
        $exception->withDriver('sqlite');

        static::assertSame('sqlite', $exception->getDriver());
    }

    /** Test: getDriver retorna null cuando no está configurado */
    public function testGetDriverReturnsNullWhenNotSet(): void
    {
        $exception = new VersaORMException('No driver');

        static::assertNull($exception->getDriver());
    }

    /** Test: getOriginMethod retorna método origen */
    public function testGetOriginMethodReturnsOriginMethod(): void
    {
        $exception = new VersaORMException('Origin test');
        $exception->withOrigin('QueryBuilder::where');

        static::assertSame('QueryBuilder::where', $exception->getOriginMethod());
    }

    /** Test: getOriginMethod retorna null cuando no está configurado */
    public function testGetOriginMethodReturnsNullWhenNotSet(): void
    {
        $exception = new VersaORMException('No origin');

        static::assertNull($exception->getOriginMethod());
    }

    /** Test: augmentDetails mezcla detalles (nuevos tienen prioridad) */
    public function testAugmentDetailsAugmentsWithNewPriority(): void
    {
        $exception = new VersaORMException('Test', 'ERROR', null, [], ['original' => 'value', 'keep' => 'this']);

        // augmentDetails da prioridad a los nuevos valores (array + operator)
        $exception->augmentDetails(['new' => 'detail', 'original' => 'should override']);

        $details = $exception->getErrorDetails();

        static::assertSame('should override', $details['original']); // New overrides
        static::assertSame('detail', $details['new']); // New added
        static::assertSame('this', $details['keep']); // Keep preserved
    }

    /** Test: toLogArray retorna array completo */
    public function testToLogArrayReturnsCompleteArray(): void
    {
        $exception = new VersaORMException(
            'Log test',
            'LOG_ERROR',
            'SELECT * FROM users',
            [1, 2],
            ['detail' => 'test'],
            '42000',
        );

        $exception->withDriver('mysql')->withOrigin('TestMethod');

        $logArray = $exception->toLogArray();

        static::assertIsArray($logArray);
        static::assertArrayHasKey('timestamp', $logArray);
        static::assertArrayHasKey('raised_at', $logArray);
        static::assertArrayHasKey('class', $logArray);
        static::assertArrayHasKey('message', $logArray);
        static::assertArrayHasKey('error_code', $logArray);
        static::assertArrayHasKey('sql_state', $logArray);
        static::assertArrayHasKey('origin_method', $logArray);
        static::assertArrayHasKey('driver', $logArray);
        static::assertArrayHasKey('query', $logArray);
        static::assertArrayHasKey('bindings', $logArray);
        static::assertArrayHasKey('details', $logArray);
        static::assertArrayHasKey('trace', $logArray);

        static::assertSame('Log test', $logArray['message']);
        static::assertSame('LOG_ERROR', $logArray['error_code']);
        static::assertSame('42000', $logArray['sql_state']);
        static::assertSame('mysql', $logArray['driver']);
        static::assertSame('TestMethod', $logArray['origin_method']);
    }

    /** Test: toLogArray incluye previous exception */
    public function testToLogArrayIncludesPreviousException(): void
    {
        $previous = new Exception('Previous error', 123);
        $exception = new VersaORMException('Main error', 'MAIN', null, [], [], null, 0, $previous);

        $logArray = $exception->toLogArray();

        static::assertIsArray($logArray['previous']);
        static::assertSame('Exception', $logArray['previous']['class']);
        static::assertSame('Previous error', $logArray['previous']['message']);
        static::assertSame(123, $logArray['previous']['code']);
    }

    /** Test: toLogArray con trace */
    public function testToLogArrayIncludesTrace(): void
    {
        $exception = new VersaORMException('Trace test');

        $logArray = $exception->toLogArray();

        static::assertIsArray($logArray['trace']);
        static::assertNotEmpty($logArray['trace']);

        $firstFrame = $logArray['trace'][0];
        static::assertArrayHasKey('i', $firstFrame);
        static::assertArrayHasKey('file', $firstFrame);
        static::assertArrayHasKey('line', $firstFrame);
        static::assertArrayHasKey('function', $firstFrame);
    }

    /** Test: Exception puede ser lanzada y capturada */
    public function testExceptionCanBeThrownAndCaught(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Catchable error');
        $this->expectExceptionCode(404);

        throw new VersaORMException('Catchable error', 'CATCHABLE', null, [], [], null, 404);
    }

    /** Test: Exception con previous exception */
    public function testExceptionWithPreviousException(): void
    {
        $previous = new Exception('Original error');
        $exception = new VersaORMException('Wrapped error', 'WRAPPED', null, [], [], null, 0, $previous);

        static::assertSame($previous, $exception->getPrevious());
        static::assertSame('Original error', $exception->getPrevious()->getMessage());
    }

    /** Test: JSON encoding de bindings en __toString */
    public function testToStringJsonEncodesBindings(): void
    {
        $bindings = [
            'string' => 'test',
            'number' => 123,
            'boolean' => true,
            'null' => null,
        ];

        $exception = new VersaORMException('JSON test', 'JSON_ERROR', 'SELECT ?', $bindings);

        $string = (string) $exception;

        // Verificar que los bindings están en formato JSON
        static::assertStringContainsString('"string":"test"', $string);
        static::assertStringContainsString('"number":123', $string);
        static::assertStringContainsString('"boolean":true', $string);
    }

    /** Test: Bindings vacíos se muestran como array vacío */
    public function testToStringWithEmptyBindingsShowsEmptyArray(): void
    {
        $exception = new VersaORMException('Empty bindings', 'EMPTY', 'SELECT * FROM users');

        $string = (string) $exception;

        static::assertStringContainsString('bindings=[]', $string);
    }

    /** Test: Múltiples excepciones tienen timestamps diferentes */
    public function testMultipleExceptionsHaveDifferentTimestamps(): void
    {
        $exception1 = new VersaORMException('First');
        usleep(1000); // 1ms de delay
        $exception2 = new VersaORMException('Second');

        static::assertNotEquals($exception1->getRaisedAt(), $exception2->getRaisedAt());

        static::assertLessThan($exception2->getRaisedAt(), $exception1->getRaisedAt());
    }

    /** Test: withDriver y withOrigin son fluent */
    public function testSetterMethodsAreFluent(): void
    {
        $exception = new VersaORMException('Fluent test');

        $result = $exception->withDriver('mysql')->withOrigin('QueryBuilder::insert');

        static::assertSame($exception, $result);
        static::assertSame('mysql', $exception->getDriver());
        static::assertSame('QueryBuilder::insert', $exception->getOriginMethod());
    }
}
