<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Regression;

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\Dialects\MySQLDialect;
use VersaORM\SQL\Dialects\PostgreSQLDialect;
use VersaORM\SQL\Dialects\SQLiteDialect;
use VersaORM\SQL\PdoEngine;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

/**
 * Regresiones de los defectos que devolvían o destruían datos incorrectos.
 *
 * Cada test corresponde a un bug reproducido en producción. Ninguno de ellos fallaba
 * con la suite anterior: todos pasaban mientras el ORM devolvía datos equivocados.
 *
 * @group sqlite
 */
final class DataCorrectnessRegressionTest extends TestCase
{
    private VersaORM $orm;

    private string $dbFile = '';

    protected function setUp(): void
    {
        // Archivo propio por test: el pool de conexiones reutiliza por DSN, así que un
        // ':memory:' compartido arrastraría estado entre tests.
        $this->dbFile = sys_get_temp_dir() . '/vorm_regr_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->orm = new VersaORM([
            'driver' => 'sqlite',
            'database' => $this->dbFile,
            'debug' => false,
        ]);
    }

    protected function tearDown(): void
    {
        $this->orm->disconnect();

        foreach (['', '-wal', '-shm'] as $suffix) {
            if (!is_file($this->dbFile . $suffix)) {
                continue;
            }

            @unlink($this->dbFile . $suffix);
        }
    }

    // ---------------------------------------------------------------------
    // union() / intersect() / except(): se descartaban cláusulas de la rama
    // ---------------------------------------------------------------------

    /**
     * union() compilaba cada rama con un generador de SQL incompleto que descartaba
     * ORDER BY y LIMIT, así que devolvía filas que la rama excluía explícitamente.
     */
    public function testUnionPreservesOrderByAndLimitOfEachBranch(): void
    {
        $this->seedKinds();

        $topOfKindA = $this->orm
            ->table('t')
            ->select(['id'])
            ->where('kind', '=', 'a')
            ->orderBy('n', 'desc')
            ->limit(1);
        $allOfKindC = $this->orm->table('t')->select(['id'])->where('kind', '=', 'c');

        $result = $topOfKindA->union($allOfKindC);
        $ids = array_column(is_array($result) ? $result : [], 'id');
        sort($ids);

        // id=3 es el de kind 'a' con mayor n; id=4 es el único kind 'c'.
        // Antes devolvía también id=1, porque el LIMIT 1 de la primera rama se perdía.
        static::assertSame([3, 4], $ids);
    }

    /**
     * El mismo generador unía todos los WHERE con AND, de modo que orWhere() se
     * convertía en AND dentro de una rama de UNION y en toSql().
     */
    public function testOrWhereIsCompiledAsOrNotAnd(): void
    {
        $this->seedKinds();

        $query = $this->orm->table('t')->select(['id'])->where('kind', '=', 'a')->orWhere('kind', '=', 'b');

        static::assertStringContainsString('OR', $query->toSql());
        static::assertStringNotContainsString('AND', $query->toSql());

        $ids = array_column($query->getAll(), 'id');
        sort($ids);
        static::assertSame([1, 2, 3], $ids);
    }

    // ---------------------------------------------------------------------
    // toSql(): mostraba un SQL distinto del que se ejecutaba
    // ---------------------------------------------------------------------

    /**
     * toSql() descartaba GROUP BY, HAVING, ORDER BY, LIMIT y OFFSET y no citaba
     * identificadores: quien depuraba con toSql() veía un SQL que no era el real.
     */
    public function testToSqlIncludesEveryClauseAndQuotesIdentifiers(): void
    {
        $sql = $this->orm
            ->table('users')
            ->select(['users.id'])
            ->where('active', '=', 1)
            ->groupBy('users.id')
            ->having('total', '>', 1)
            ->orderBy('users.id', 'desc')
            ->limit(10)
            ->offset(5)
            ->toSql();

        foreach (['GROUP BY', 'HAVING', 'ORDER BY', 'LIMIT 10', 'OFFSET 5'] as $clause) {
            static::assertStringContainsString($clause, $sql, sprintf('falta %s en toSql()', $clause));
        }
        static::assertStringContainsString('"users"."id"', $sql, 'los identificadores deben ir citados');
    }

    /** Un identificador que es palabra reservada sólo funciona si va citado. */
    public function testReservedWordIdentifiersRoundTrip(): void
    {
        $this->orm->exec('CREATE TABLE "order" (id INTEGER PRIMARY KEY, "group" TEXT)');
        $this->orm->exec('INSERT INTO "order" VALUES (1, \'g\')');

        $rows = $this->orm->table('order')->select(['id', 'group'])->getAll();

        static::assertSame([['id' => 1, 'group' => 'g']], $rows);
    }

    /** Los valores de whereIn se expanden a un placeholder por valor. */
    public function testWhereInExpandsOnePlaceholderPerValue(): void
    {
        $query = $this->orm->table('t')->select(['id'])->whereIn('id', [1, 2, 3]);

        static::assertStringContainsString('IN (?, ?, ?)', $query->toSql());
        static::assertSame([1, 2, 3], $query->getBindings());
    }

    // ---------------------------------------------------------------------
    // UPDATE / DELETE: el predicado se reinterpretaba en silencio
    // ---------------------------------------------------------------------

    /**
     * El calificador de columna se quitaba adivinando ("los alias suelen ser cortos"),
     * así que `where('accounts.id', ...)->delete()` sobre `users` se convertía en
     * `DELETE FROM users WHERE id = ...`: borraba una fila de la tabla equivocada.
     */
    public function testDeleteRejectsQualifierOfAnotherTableInsteadOfWideningThePredicate(): void
    {
        $this->seedUsers();

        try {
            $this->orm->table('users')->where('accounts.id', '=', 1)->delete();
            static::fail('Se esperaba una excepción en vez de reinterpretar el predicado');
        } catch (VersaORMException $e) {
            static::assertStringContainsString('accounts.id', $e->getMessage());
        }

        // Lo esencial: no se borró nada.
        static::assertCount(3, $this->orm->table('users')->getAll());
    }

    /** @return array<string, array{0: string, 1: string}> */
    public static function legitimateQualifiers(): array
    {
        return [
            'sin calificador' => ['users', 'id'],
            'calificado con la tabla' => ['users', 'users.id'],
            'calificado con el alias' => ['users as u', 'u.id'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('legitimateQualifiers')]
    public function testDeleteAcceptsQualifiersOfItsOwnTable(string $from, string $column): void
    {
        $this->seedUsers();

        $this->orm->table($from)->where($column, '=', 1)->delete();

        static::assertCount(2, $this->orm->table('users')->getAll());
    }

    // ---------------------------------------------------------------------
    // Inyección
    // ---------------------------------------------------------------------

    /**
     * on() guardaba el operador sin validarlo y SqlGenerator lo interpolaba crudo:
     * un operador malicioso convertía el JOIN en un producto cartesiano.
     */
    public function testOnRejectsOperatorsOutsideTheAllowlist(): void
    {
        $this->orm->exec('CREATE TABLE users (id INTEGER PRIMARY KEY)');
        $this->orm->exec('CREATE TABLE accounts (id INTEGER PRIMARY KEY, uid INT)');

        $query = $this->orm->table('users')->join('accounts', 'users.id', '=', 'accounts.uid');

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid operator in ON condition');
        $query->on('users.id', '= 1 OR 1=1 OR users.id =', 'accounts.uid');
    }

    /**
     * La rama `tabla.*` de quoteIdentifier() se saltaba el escape del delimitador, con
     * lo que el nombre de la tabla podía cerrar la cita e inyectar SQL.
     */
    public function testQuoteIdentifierEscapesBothPartsOfATableStar(): void
    {
        $cases = [
            [new MySQLDialect(), 'x`,(SELECT 1),`y.*', '`x``,(SELECT 1),``y`.*'],
            [new PostgreSQLDialect(), 'x",(SELECT 1),"y.*', '"x"",(SELECT 1),""y".*'],
            [new SQLiteDialect(), 'x",(SELECT 1),"y.*', '"x"",(SELECT 1),""y".*'],
        ];

        foreach ($cases as [$dialect, $input, $expected]) {
            static::assertSame($expected, $dialect->quoteIdentifier($input), $dialect->getName());
        }
    }

    /** upsertMany() no validaba las claves de los registros, que vienen del llamador. */
    public function testUpsertManyValidatesRecordColumnNames(): void
    {
        $this->orm->exec('CREATE TABLE u (id INTEGER PRIMARY KEY, name TEXT)');

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Invalid or malicious column name detected');
        $this->orm->table('u')->upsertMany([['id' => 1, 'x`,(SELECT 1),`y.*' => 'v']], ['id']);
    }

    // ---------------------------------------------------------------------
    // Fuga de credenciales
    // ---------------------------------------------------------------------

    /**
     * El SQL y todos los bindings se incrustaban en el mensaje de la excepción, y
     * HandlesErrors::formatErrorForApi() devuelve ese mensaje al cliente HTTP incluso
     * con debug desactivado.
     */
    public function testBindingsNeverAppearInTheExceptionMessage(): void
    {
        $this->orm->exec('CREATE TABLE u (id INTEGER PRIMARY KEY, email TEXT UNIQUE, pass TEXT)');
        $secret = 'SUPERSECRET_HASH_XYZ';
        $this->orm->table('u')->insert(['email' => 'a@b.com', 'pass' => $secret]);

        try {
            $this->orm->table('u')->insert(['email' => 'a@b.com', 'pass' => $secret]);
            static::fail('Se esperaba una violación de UNIQUE');
        } catch (VersaORMException $e) {
            static::assertStringNotContainsString($secret, $e->getMessage());
            // Pero sigue disponible de forma estructurada, donde sí se sanitiza al loguear.
            static::assertContains($secret, $e->getBindings());
        }
    }

    // ---------------------------------------------------------------------
    // Rendimiento: el esquema se introspeccionaba una vez por fila
    // ---------------------------------------------------------------------

    /**
     * El caché de esquema vivía en una propiedad de instancia y get() creaba un modelo
     * por fila, así que una consulta de N filas disparaba N introspecciones
     * (SHOW FULL COLUMNS / PRAGMA). Es la guarda más aguda contra la regresión: el número
     * de sentencias ejecutadas tiene que depender de la consulta, no de las filas.
     */
    public function testSchemaIntrospectionDoesNotScaleWithRowCount(): void
    {
        $this->orm->exec('CREATE TABLE big (id INTEGER PRIMARY KEY, name TEXT, n INT)');
        $records = [];

        for ($i = 1; $i <= 200; $i++) {
            $records[] = ['name' => 'n' . $i, 'n' => $i];
        }
        $this->orm->table('big')->insertMany($records, 200);

        $before = PdoEngine::getMetrics();
        $rows = $this->orm->table('big')->getAll();
        $after = PdoEngine::getMetrics();

        static::assertCount(200, $rows);

        $statements =
            $after['stmt_cache_hits'] - $before['stmt_cache_hits']
            + ($after['stmt_cache_misses'] - $before['stmt_cache_misses']);

        // Antes esto era 201 para 200 filas. Se deja holgura para el SELECT y la
        // introspección inicial, pero tiene que quedar muy por debajo del número de filas.
        static::assertLessThan(
            10,
            $statements,
            sprintf('Se ejecutaron %d sentencias para 200 filas: la introspección volvió a ser por fila', $statements),
        );
    }

    /**
     * El caso que el issue señala como más fácil de pasar por alto: el modelo declara
     * todos sus tipos, pero la consulta trae un alias o una columna calculada. Ese alias
     * nunca está en el esquema de la tabla, así que forzaba la introspección igualmente
     * —y, al ser la caché de instancia, una vez por fila.
     */
    public function testAliasColumnDoesNotForceSchemaLookupPerRow(): void
    {
        $this->orm->exec('CREATE TABLE ali (id INTEGER PRIMARY KEY, nombre TEXT)');
        $records = [];

        for ($i = 1; $i <= 150; $i++) {
            $records[] = ['nombre' => 'n' . $i];
        }
        $this->orm->table('ali')->insertMany($records, 150);

        $before = PdoEngine::getMetrics();
        $rows = $this->orm
            ->table('ali')
            ->select(['id', 'nombre'])
            ->selectRaw('COUNT(*) OVER() AS total_count')
            ->getAll();
        $after = PdoEngine::getMetrics();

        static::assertCount(150, $rows);
        static::assertArrayHasKey('total_count', $rows[0]);

        $statements =
            $after['stmt_cache_hits'] - $before['stmt_cache_hits']
            + ($after['stmt_cache_misses'] - $before['stmt_cache_misses']);

        static::assertLessThan(
            10,
            $statements,
            sprintf('%d sentencias para 150 filas: la introspección volvió a ser por fila', $statements),
        );
    }

    /**
     * clearDatabaseSchemaCache() sólo limpiaba la copia de la instancia, así que la
     * caché compartida del proceso seguía devolviendo el esquema antiguo.
     */
    public function testClearingTheModelSchemaCacheAlsoClearsTheSharedOne(): void
    {
        $this->orm->exec('CREATE TABLE sc (id INTEGER PRIMARY KEY, a TEXT)');
        $this->orm->table('sc')->insert(['a' => 'x']);
        // Calienta la caché compartida.
        $this->orm->table('sc')->getAll();

        $this->orm->exec('ALTER TABLE sc ADD COLUMN b INTEGER');
        $this->orm->table('sc')->insert(['a' => 'y', 'b' => 7]);

        $rows = $this->orm->table('sc')->getAll();
        static::assertArrayHasKey('b', $rows[1], 'la columna nueva debe verse tras el DDL');
        static::assertSame(7, $rows[1]['b']);
    }

    // ---------------------------------------------------------------------

    private function seedKinds(): void
    {
        $this->orm->exec('CREATE TABLE t (id INTEGER PRIMARY KEY, kind TEXT, n INT)');

        foreach ([[1, 'a', 5], [2, 'b', 1], [3, 'a', 9], [4, 'c', 2]] as $row) {
            $this->orm->exec('INSERT INTO t VALUES (?, ?, ?)', $row);
        }
    }

    private function seedUsers(): void
    {
        $this->orm->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, n TEXT)');

        foreach ([1, 2, 3] as $id) {
            $this->orm->exec('INSERT INTO users VALUES (?, ?)', [$id, 'u' . $id]);
        }
    }
}
