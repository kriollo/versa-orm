<?php

declare(strict_types=1);

namespace VersaORM\SQL;

use function in_array;
use function strlen;

/**
 * Parser único de expresiones de proyección (select / groupBy / orderBy / having / where).
 *
 * Antes la validación y la compilación parseaban el mismo string con reglas distintas:
 * QueryBuilder::isSafeIdentifier() y SqlGenerator::compileSelectPart() hacían cada uno su
 * propio `preg_split('/\s+as\s+/i')` y discrepaban sobre qué significaba la expresión. De
 * ahí venían tanto los rechazos de SQL legítimo (`CAST(x AS CHAR) AS y`) como el riesgo de
 * que el validador aprobara una cosa y el compilador emitiera otra.
 *
 * Ahora hay un solo parser y ambos lo usan, así que no pueden discrepar.
 *
 * Una expresión se clasifica en exactamente una forma:
 *
 *  - `star`:       `*`
 *  - `identifier`: `col`, `tbl.col`, `tbl.*`, `schema.tbl.col` — se cita con el dialecto,
 *                  por lo que acentos, espacios y palabras reservadas son seguros.
 *  - `function`:   `FUNC(...)` y aritmética entre funciones/columnas. Se emite tal cual,
 *                  así que ésta es la frontera de seguridad y lleva allowlist.
 *
 * Cualquier otra cosa devuelve null: el llamador debe usar `selectRaw()` explícitamente.
 */
final class SelectExpression
{
    /**
     * Funciones permitidas dentro de una expresión de proyección.
     *
     * Ampliada respecto de la lista original de 30 para cubrir lo que se rechazaba:
     * CAST, DATE_FORMAT, JSON_*, agregación con separador, condicionales y matemáticas.
     */
    private const ALLOWED_FUNCTIONS = [
        // agregación
        'COUNT',
        'SUM',
        'AVG',
        'MAX',
        'MIN',
        'GROUP_CONCAT',
        'STRING_AGG',
        'ARRAY_AGG',
        'STDDEV',
        'VARIANCE',
        'VAR_POP',
        'VAR_SAMP',
        'STDDEV_POP',
        'STDDEV_SAMP',
        // texto
        'UPPER',
        'LOWER',
        'LENGTH',
        'CHAR_LENGTH',
        'SUBSTRING',
        'SUBSTR',
        'CONCAT',
        'CONCAT_WS',
        'TRIM',
        'LTRIM',
        'RTRIM',
        'REPLACE',
        'LPAD',
        'RPAD',
        'REVERSE',
        'LEFT',
        'RIGHT',
        'INITCAP',
        'MD5',
        // null / condicional
        'COALESCE',
        'IFNULL',
        'NULLIF',
        'NVL',
        'IF',
        'IIF',
        'GREATEST',
        'LEAST',
        'CASE',
        // numérico
        'ABS',
        'ROUND',
        'CEIL',
        'CEILING',
        'FLOOR',
        'POWER',
        'POW',
        'SQRT',
        'EXP',
        'LN',
        'LOG',
        'LOG10',
        'MOD',
        'SIGN',
        'TRUNCATE',
        'RANDOM',
        // fecha y hora
        'NOW',
        'CURDATE',
        'CURTIME',
        'CURRENT_DATE',
        'CURRENT_TIME',
        'CURRENT_TIMESTAMP',
        'DATE',
        'TIME',
        'YEAR',
        'MONTH',
        'DAY',
        'HOUR',
        'MINUTE',
        'SECOND',
        'WEEK',
        'QUARTER',
        'DAYOFWEEK',
        'DAYOFYEAR',
        'DATE_FORMAT',
        'DATE_TRUNC',
        'DATE_PART',
        'DATE_ADD',
        'DATE_SUB',
        'DATEDIFF',
        'TIMESTAMPDIFF',
        'EXTRACT',
        'AGE',
        'TO_CHAR',
        'TO_DATE',
        'TO_TIMESTAMP',
        'UNIX_TIMESTAMP',
        'FROM_UNIXTIME',
        // conversión
        'CAST',
        'CONVERT',
        'TO_NUMBER',
        // json
        'JSON_EXTRACT',
        'JSON_VALUE',
        'JSON_QUOTE',
        'JSON_UNQUOTE',
        'JSON_ARRAY',
        'JSON_OBJECT',
        'JSON_LENGTH',
        'JSON_CONTAINS',
        'JSON_KEYS',
        'JSON_TYPE',
        'JSONB_EXTRACT_PATH',
        'JSONB_ARRAY_LENGTH',
        // otros
        'DISTINCT',
        'ANY_VALUE',
    ];

    /**
     * Palabras que no pueden aparecer en una expresión de proyección: son las que
     * permitirían abrir una subconsulta o encadenar otra sentencia.
     */
    private const FORBIDDEN_KEYWORDS = [
        // 'FROM' no está en la lista: aparece legítimamente dentro de EXTRACT(... FROM ...),
        // SUBSTRING(... FROM ... FOR ...) y TRIM(... FROM ...), y sin SELECT —que sí está
        // prohibido— no permite formar una subconsulta.
        'SELECT',
        'UNION',
        'INTERSECT',
        'EXCEPT',
        'WHERE',
        'JOIN',
        'HAVING',
        'INSERT',
        'UPDATE',
        'DELETE',
        'DROP',
        'ALTER',
        'CREATE',
        'TRUNCATE',
        'REPLACE',
        'GRANT',
        'REVOKE',
        'EXEC',
        'EXECUTE',
        'CALL',
        'MERGE',
        'INTO',
        'VALUES',
        'LIMIT',
        'OFFSET',
        'SLEEP',
        'BENCHMARK',
        'LOAD_FILE',
        'OUTFILE',
        'DUMPFILE',
        'INFORMATION_SCHEMA',
        'PG_SLEEP',
        'WAITFOR',
        'XP_CMDSHELL',
    ];

    /**
     * Parsea una expresión de proyección.
     *
     * @return array{kind: 'star'|'identifier'|'function', expr: string, parts: list<string>, alias: string|null}|null
     *         null si la expresión no es representable de forma segura
     */
    public static function parse(string $expression): ?array
    {
        $expr = trim($expression);

        if ($expr === '') {
            return null;
        }

        // Los comentarios y el punto y coma no tienen lugar en una proyección, y son
        // el vehículo habitual para encadenar sentencias.
        if (self::hasCommentOrStatementBreak($expr)) {
            return null;
        }
        [$left, $alias] = self::splitAlias($expr);

        if ($left === '') {
            return null;
        }

        if ($alias !== null && !self::isUsableAlias($alias)) {
            return null;
        }

        if ($left === '*') {
            return ['kind' => 'star', 'expr' => '*', 'parts' => [], 'alias' => $alias];
        }
        $parts = self::asIdentifierParts($left);

        if ($parts !== null) {
            return ['kind' => 'identifier', 'expr' => $left, 'parts' => $parts, 'alias' => $alias];
        }

        if (self::isSafeFunctionExpression($left)) {
            return ['kind' => 'function', 'expr' => $left, 'parts' => [], 'alias' => $alias];
        }

        return null;
    }

    /** Atajo para los llamadores que sólo necesitan saber si la expresión es admisible. */
    public static function isValid(string $expression): bool
    {
        return self::parse($expression) !== null;
    }

    /**
     * Parsea una referencia de tabla: `tabla`, `schema.tabla`, `tabla AS alias`
     * o `tabla alias` (alias implícito, sin AS).
     *
     * @return array{table: string, alias: string|null}|null
     */
    public static function parseTableReference(string $table): ?array
    {
        $t = trim($table);

        if ($t === '') {
            return null;
        }

        // Alias implícito: "tabla alias". Se normaliza a la forma con AS para que lo
        // resuelva el mismo parser y no haya una segunda gramática que mantener.
        if (preg_match('/^(\S+)\s+(\S+)$/', $t, $m) === 1 && strtoupper($m[2]) !== 'AS') {
            $t = $m[1] . ' AS ' . $m[2];
        }
        $parsed = self::parse($t);

        if ($parsed === null || $parsed['kind'] !== 'identifier') {
            return null;
        }

        // `tabla.*` no es una referencia de tabla válida.
        if (in_array('*', $parsed['parts'], true)) {
            return null;
        }

        return ['table' => $parsed['expr'], 'alias' => $parsed['alias']];
    }

    /**
     * Separa `<expr> AS <alias>` usando el ` AS ` de nivel superior.
     *
     * Un `preg_split` sobre `/\s+as\s+/i` rompe `CAST(x AS CHAR)` y cualquier literal que
     * contenga " as ", que es exactamente el bug original.
     *
     * @return array{0: string, 1: string|null}
     */
    private static function splitAlias(string $expr): array
    {
        $depth = 0;
        $len = strlen($expr);
        $quote = null;

        for ($i = 0; $i < $len; $i++) {
            $c = $expr[$i];

            if ($quote !== null) {
                // Dentro de un literal: '' y "" son el escape del propio delimitador.
                if ($c === $quote) {
                    if (($i + 1) < $len && $expr[$i + 1] === $quote) {
                        $i++;

                        continue;
                    }
                    $quote = null;
                }

                continue;
            }

            if ($c === "'" || $c === '"' || $c === '`') {
                $quote = $c;

                continue;
            }

            if ($c === '(') {
                $depth++;

                continue;
            }

            if ($c === ')') {
                $depth--;

                continue;
            }

            // Sólo partimos en el ` AS ` de nivel superior.
            if ($depth !== 0 || $i === 0) {
                continue;
            }

            if (!self::matchesAsAt($expr, $i, $len)) {
                continue;
            }
            $left = rtrim(substr($expr, 0, $i));
            $alias = ltrim(substr($expr, $i + 4));

            return [$left, $alias === '' ? null : $alias];
        }

        // Literal sin cerrar: no es una expresión válida.
        if ($quote !== null || $depth !== 0) {
            return ['', null];
        }

        return [$expr, null];
    }

    /** ¿Hay un ` AS ` (con espacio a ambos lados) en la posición dada? */
    private static function matchesAsAt(string $expr, int $i, int $len): bool
    {
        if (($i + 4) > ($len - 1)) {
            return false;
        }

        if (!self::isSpace($expr[$i])) {
            return false;
        }
        $kw = substr($expr, $i + 1, 2);

        if (strtoupper($kw) !== 'AS') {
            return false;
        }

        return self::isSpace($expr[$i + 3]);
    }

    private static function isSpace(string $c): bool
    {
        return $c === ' ' || $c === "\t" || $c === "\n" || $c === "\r";
    }

    /**
     * Un alias se cita siempre con el dialecto, así que basta con exigir que no esté
     * vacío y no traiga caracteres de control ni el delimitador sin escapar. Eso habilita
     * acentos (`año`), espacios (`"Total Ventas"`) y alias que empiezan por dígito.
     */
    private static function isUsableAlias(string $alias): bool
    {
        $a = trim($alias, " \t\n\r`\"'");

        if ($a === '' || strlen($a) > 128) {
            return false;
        }

        // Un alias es un nombre, no una expresión: ni paréntesis, ni comas, ni
        // delimitadores de cita en el interior. Sin esto, `id AS x\`, (SELECT 1) AS \`y`
        // pasaba como alias (el quoting lo dejaba inerte, pero no hay por qué depender
        // sólo de eso), y `COUNT(*) AS a, (SELECT 1) AS b` también.
        if (preg_match('/[(),;`\'"]/', $a) === 1) {
            return false;
        }

        // Caracteres de control: nada legítimo los usa y confunden a los quoters.
        return preg_match('/[\x00-\x1F\x7F]/', $a) !== 1;
    }

    /**
     * Devuelve los segmentos si la expresión es un identificador (posiblemente calificado).
     *
     * No se valida la forma de cada segmento: el compilador los cita, y eso es lo que los
     * hace seguros. Sólo se rechaza lo que rompería el quoting o abriría otra sentencia.
     *
     * @return list<string>|null
     */
    private static function asIdentifierParts(string $expr): ?array
    {
        // Un identificador no lleva paréntesis, operadores ni comas.
        if (preg_match('/[()+\-*\/%,\'"`\s=<>|&!~^]/', $expr) === 1) {
            // `tbl.*` es la única forma con `*` admitida como identificador.
            if (preg_match('/^[^()+\-*\/%,\'"`\s=<>|&!~^]+\.\*$/', $expr) !== 1) {
                return null;
            }
        }
        /** @var list<string> $parts */
        $parts = explode('.', $expr);

        if (count($parts) > 4) {
            return null;
        }

        foreach ($parts as $i => $part) {
            if ($part === '') {
                return null;
            }

            // `*` sólo vale como último segmento (`tbl.*`).
            if ($part === '*') {
                if ($i !== (count($parts) - 1)) {
                    return null;
                }

                continue;
            }

            if (strlen($part) > 128 || preg_match('/[\x00-\x1F\x7F]/', $part) === 1) {
                return null;
            }
        }

        return $parts;
    }

    /**
     * Valida una expresión que se emitirá cruda en el SQL.
     *
     * Tres condiciones a la vez, que juntas impiden formar una subconsulta o encadenar:
     *  1. todo `nombre(` debe estar en la allowlist de funciones,
     *  2. ninguna palabra prohibida fuera de literales,
     *  3. sólo caracteres de expresión, literales bien cerrados y paréntesis balanceados.
     */
    private static function isSafeFunctionExpression(string $expr): bool
    {
        if (strlen($expr) > 1000) {
            return false;
        }
        $stripped = self::stripLiterals($expr);

        if ($stripped === null) {
            return false; // literal sin cerrar
        }

        // Debe parecer una expresión con al menos una llamada a función.
        if (!str_contains($stripped, '(')) {
            return false;
        }

        if (substr_count($stripped, '(') !== substr_count($stripped, ')')) {
            return false;
        }

        // 1. Toda función invocada debe estar permitida.
        if (preg_match_all('/([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $stripped, $m) !== false) {
            foreach ($m[1] as $fn) {
                if (!in_array(strtoupper($fn), self::ALLOWED_FUNCTIONS, true)) {
                    return false;
                }
            }
        }

        // 2. Ninguna palabra prohibida.
        foreach (self::FORBIDDEN_KEYWORDS as $kw) {
            if (preg_match('/\b' . $kw . '\b/i', $stripped) === 1) {
                return false;
            }
        }

        // 2b. 'FROM' sólo es legítimo dentro de la llamada a una función
        // (EXTRACT(YEAR FROM x), SUBSTRING(x FROM 1 FOR 2)). En el nivel superior
        // no tiene sentido en una proyección y produciría SQL malformado.
        if (self::hasTopLevelKeyword($stripped, 'FROM')) {
            return false;
        }

        // 3. Sólo caracteres propios de una expresión. El marcador de literal es '?'.
        return preg_match('/^[A-Za-z0-9_.,()\s*+\-\/%?:]+$/', $stripped) === 1;
    }

    /** ¿Aparece la palabra dada fuera de cualquier paréntesis? (entrada sin literales) */
    private static function hasTopLevelKeyword(string $stripped, string $keyword): bool
    {
        $depth = 0;
        $len = strlen($stripped);
        $kwLen = strlen($keyword);

        for ($i = 0; $i < $len; $i++) {
            $c = $stripped[$i];

            if ($c === '(') {
                $depth++;

                continue;
            }

            if ($c === ')') {
                $depth--;

                continue;
            }

            if ($depth !== 0) {
                continue;
            }

            if (strtoupper(substr($stripped, $i, $kwLen)) !== $keyword) {
                continue;
            }
            $before = $i === 0 ? ' ' : $stripped[$i - 1];
            $after = ($i + $kwLen) >= $len ? ' ' : $stripped[$i + $kwLen];

            if (preg_match('/[A-Za-z0-9_]/', $before) !== 1 && preg_match('/[A-Za-z0-9_]/', $after) !== 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Reemplaza cada literal por '?' para poder analizar la estructura sin que el
     * contenido de los literales (inerte) provoque falsos positivos.
     *
     * Devuelve null si queda un literal sin cerrar.
     */
    private static function stripLiterals(string $expr): ?string
    {
        $out = '';
        $len = strlen($expr);
        $quote = null;

        for ($i = 0; $i < $len; $i++) {
            $c = $expr[$i];

            if ($quote === null) {
                if ($c === "'" || $c === '"' || $c === '`') {
                    $quote = $c;
                    $out .= '?';

                    continue;
                }
                $out .= $c;

                continue;
            }

            if ($c !== $quote) {
                continue;
            }

            if (($i + 1) < $len && $expr[$i + 1] === $quote) {
                $i++;

                continue;
            }
            $quote = null;
        }

        return $quote === null ? $out : null;
    }

    /** Comentarios SQL y fin de sentencia: nunca válidos en una proyección. */
    private static function hasCommentOrStatementBreak(string $expr): bool
    {
        return self::hasStatementBreak($expr);
    }

    /**
     * ¿La expresión encadena otra sentencia o esconde un comentario?
     *
     * Es lo único que una expresión raw no puede contener nunca: con `;` se encadena otra
     * sentencia y con un comentario se desactiva el resto de la consulta. Se analiza
     * fuera de los literales, porque un `--` dentro de una cadena es texto inerte.
     *
     * Un literal sin cerrar cuenta como ruptura: deja la consulta en un estado en que lo
     * que sigue se interpreta como SQL.
     */
    public static function hasStatementBreak(string $expr): bool
    {
        $stripped = self::stripLiterals($expr);

        if ($stripped === null) {
            return true;
        }

        return (
            str_contains($stripped, ';')
            || str_contains($stripped, '--')
            || str_contains($stripped, '/*')
            || str_contains($stripped, '*/')
            || str_contains($stripped, '#')
        );
    }

    /**
     * ¿Están balanceados los paréntesis, ignorando los que viven dentro de literales?
     *
     * Contar con substr_count sobre la cadena cruda da falsos negativos en cuanto un
     * literal contiene un paréntesis suelto, p.ej. `CONCAT(a, ' :) ')`.
     */
    public static function hasBalancedParentheses(string $expr): bool
    {
        $stripped = self::stripLiterals($expr);

        if ($stripped === null) {
            return false;
        }

        return substr_count($stripped, '(') === substr_count($stripped, ')');
    }
}
