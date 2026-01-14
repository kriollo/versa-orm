<?php

declare(strict_types=1);

namespace VersaORM\Schema;

/**
 * TypeMapper maneja el mapeo transparente de tipos de datos entre diferentes motores de base de datos.
 *
 * Esta clase se encarga de convertir tipos de datos abstractos (como 'string', 'integer', etc.)
 * a los tipos específicos de cada motor de base de datos (MySQL, PostgreSQL, SQLite).
 */
class TypeMapper
{
    /**
     * Mapeo de tipos abstractos a tipos específicos por motor.
     */
    private const TYPE_MAPPINGS = [
        'mysql' => [
            'bigIncrements' => 'BIGINT UNSIGNED',
            'bigInteger' => 'BIGINT',
            'binary' => 'BLOB',
            'boolean' => 'TINYINT(1)',
            'char' => 'CHAR',
            'date' => 'DATE',
            'dateTime' => 'DATETIME',
            'decimal' => 'DECIMAL',
            'double' => 'DOUBLE',
            'enum' => 'ENUM',
            'float' => 'FLOAT',
            'geometry' => 'GEOMETRY',
            'id' => 'BIGINT UNSIGNED',
            'increments' => 'INT UNSIGNED',
            'integer' => 'INT',
            'ipAddress' => 'VARCHAR(45)',
            'json' => 'JSON',
            'longText' => 'LONGTEXT',
            'macAddress' => 'VARCHAR(17)',
            'mediumIncrements' => 'MEDIUMINT UNSIGNED',
            'mediumInteger' => 'MEDIUMINT',
            'mediumText' => 'MEDIUMTEXT',
            'morphs' => ['BIGINT UNSIGNED', 'VARCHAR(255)'], // Para _id y _type
            'rememberToken' => 'VARCHAR(100)',
            'set' => 'SET',
            'smallIncrements' => 'SMALLINT UNSIGNED',
            'smallInteger' => 'SMALLINT',
            'string' => 'VARCHAR',
            'text' => 'TEXT',
            'time' => 'TIME',
            'timestamp' => 'TIMESTAMP',
            'timestamps' => ['TIMESTAMP', 'TIMESTAMP'], // Para created_at y updated_at
            'tinyIncrements' => 'TINYINT UNSIGNED AUTO_INCREMENT',
            'tinyInteger' => 'TINYINT',
            'tinyText' => 'TINYTEXT',
            'unsignedBigInteger' => 'BIGINT UNSIGNED',
            'unsignedInteger' => 'INT UNSIGNED',
            'unsignedMediumInteger' => 'MEDIUMINT UNSIGNED',
            'unsignedSmallInteger' => 'SMALLINT UNSIGNED',
            'unsignedTinyInteger' => 'TINYINT UNSIGNED',
            'uuid' => 'CHAR(36)',
            'year' => 'YEAR',
        ],
        'postgresql' => [
            'bigIncrements' => 'BIGSERIAL',
            'bigInteger' => 'BIGINT',
            'binary' => 'BYTEA',
            'boolean' => 'BOOLEAN',
            'char' => 'CHAR',
            'date' => 'DATE',
            'dateTime' => 'TIMESTAMP',
            'decimal' => 'DECIMAL',
            'double' => 'DOUBLE PRECISION',
            'enum' => 'VARCHAR', // PostgreSQL usa CHECK constraints para enums
            'float' => 'REAL',
            'geometry' => 'GEOMETRY',
            'id' => 'BIGSERIAL',
            'increments' => 'SERIAL',
            'integer' => 'INTEGER',
            'ipAddress' => 'INET',
            'json' => 'JSON',
            'longText' => 'TEXT',
            'macAddress' => 'MACADDR',
            'mediumIncrements' => 'SERIAL',
            'mediumInteger' => 'INTEGER',
            'mediumText' => 'TEXT',
            'morphs' => ['BIGINT', 'VARCHAR(255)'],
            'rememberToken' => 'VARCHAR(100)',
            'set' => 'TEXT', // PostgreSQL no tiene SET nativo
            'smallIncrements' => 'SMALLSERIAL',
            'smallInteger' => 'SMALLINT',
            'string' => 'VARCHAR',
            'text' => 'TEXT',
            'time' => 'TIME',
            'timestamp' => 'TIMESTAMP',
            'timestamps' => ['TIMESTAMP', 'TIMESTAMP'],
            'tinyIncrements' => 'SMALLSERIAL',
            'tinyInteger' => 'SMALLINT',
            'tinyText' => 'TEXT',
            'unsignedBigInteger' => 'BIGINT',
            'unsignedInteger' => 'INTEGER',
            'unsignedMediumInteger' => 'INTEGER',
            'unsignedSmallInteger' => 'SMALLINT',
            'unsignedTinyInteger' => 'SMALLINT',
            'uuid' => 'UUID',
            'year' => 'INTEGER',
        ],
        'sqlite' => [
            'bigIncrements' => 'INTEGER',
            'bigInteger' => 'INTEGER',
            'binary' => 'BLOB',
            'boolean' => 'INTEGER',
            'char' => 'TEXT',
            'date' => 'TEXT',
            'dateTime' => 'TEXT',
            'decimal' => 'NUMERIC',
            'double' => 'REAL',
            'enum' => 'TEXT',
            'float' => 'REAL',
            'geometry' => 'TEXT', // SQLite no tiene tipos geométricos nativos
            'id' => 'INTEGER',
            'increments' => 'INTEGER',
            'integer' => 'INTEGER',
            'ipAddress' => 'TEXT',
            'json' => 'TEXT',
            'longText' => 'TEXT',
            'macAddress' => 'TEXT',
            'mediumIncrements' => 'INTEGER',
            'mediumInteger' => 'INTEGER',
            'mediumText' => 'TEXT',
            'morphs' => ['INTEGER', 'TEXT'],
            'rememberToken' => 'TEXT',
            'set' => 'TEXT',
            'smallIncrements' => 'INTEGER',
            'smallInteger' => 'INTEGER',
            'string' => 'TEXT',
            'text' => 'TEXT',
            'time' => 'TEXT',
            'timestamp' => 'TEXT',
            'timestamps' => ['TEXT', 'TEXT'],
            'tinyIncrements' => 'INTEGER',
            'tinyInteger' => 'INTEGER',
            'tinyText' => 'TEXT',
            'unsignedBigInteger' => 'INTEGER',
            'unsignedInteger' => 'INTEGER',
            'unsignedMediumInteger' => 'INTEGER',
            'unsignedSmallInteger' => 'INTEGER',
            'unsignedTinyInteger' => 'INTEGER',
            'uuid' => 'TEXT',
            'year' => 'INTEGER',
        ],
    ];

    /**
     * Mapea un tipo abstracto al tipo específico del motor de base de datos.
     *
     * @param string $abstractType Tipo abstracto (ej: 'string', 'integer')
     * @param string $driver Motor de base de datos ('mysql', 'postgresql', 'sqlite')
     * @param array<string, mixed> $options Opciones adicionales (length, precision, etc.)
     *
     * @return array<string>|string Tipo específico del motor o array para tipos múltiples
     */
    public static function mapType(string $abstractType, string $driver, array $options = []): string|array
    {
        $normalizedDriver = self::normalizeDriver($driver);

        if (!isset(self::TYPE_MAPPINGS[$normalizedDriver])) {
            throw new \InvalidArgumentException("Unsupported database driver: {$driver}");
        }

        if (!isset(self::TYPE_MAPPINGS[$normalizedDriver][$abstractType])) {
            throw new \InvalidArgumentException("Unsupported column type: {$abstractType}");
        }

        $baseType = self::TYPE_MAPPINGS[$normalizedDriver][$abstractType];

        // Si es un array (para tipos múltiples como morphs o timestamps), retornarlo directamente
        if (is_array($baseType)) {
            return $baseType;
        }

        // Aplicar opciones específicas del tipo
        return self::applyTypeOptions($baseType, $abstractType, $options, $normalizedDriver);
    }

    /**
     * Obtiene la lista de tipos soportados para un motor específico.
     *
     * @param string $driver Motor de base de datos
     *
     * @return array<string> Lista de tipos soportados
     */
    public static function getSupportedTypes(string $driver): array
    {
        $normalizedDriver = self::normalizeDriver($driver);

        return array_keys(self::TYPE_MAPPINGS[$normalizedDriver]);
    }

    /**
     * Verifica si un tipo está soportado para un motor específico.
     */
    public static function isTypeSupported(string $type, string $driver): bool
    {
        try {
            $normalizedDriver = self::normalizeDriver($driver);

            return isset(self::TYPE_MAPPINGS[$normalizedDriver][$type]);
        } catch (\InvalidArgumentException) {
            return false;
        }
    }

    /**
     * Obtiene información de compatibilidad entre motores para un tipo específico.
     *
     * @return array<string, array<string>|string> Mapeo de driver a tipo SQL
     */
    public static function getTypeCompatibility(string $abstractType): array
    {
        $compatibility = [];

        foreach (self::TYPE_MAPPINGS as $driver => $types) {
            if (!isset($types[$abstractType])) {
                continue;
            }

            $compatibility[$driver] = $types[$abstractType];
        }

        return $compatibility;
    }

    /**
     * Normaliza el nombre del driver para mapeo consistente.
     */
    private static function normalizeDriver(string $driver): string
    {
        return match (strtolower($driver)) {
            'mysql', 'mariadb' => 'mysql',
            'pgsql', 'postgres', 'postgresql' => 'postgresql',
            'sqlite' => 'sqlite',
            default => throw new \InvalidArgumentException("Unsupported database driver: {$driver}"),
        };
    }

    /**
     * Aplica opciones específicas al tipo base (longitud, precisión, etc.).
     *
     * @param array<string, mixed> $options
     */
    private static function applyTypeOptions(
        string $baseType,
        string $abstractType,
        array $options,
        string $driver,
    ): string {
        $result = $baseType;

        // Aplicar longitud para tipos que la soportan
        if (isset($options['length']) && self::supportsLength($abstractType)) {
            if (str_starts_with($result, 'VARCHAR')) {
                $result = "VARCHAR({$options['length']})";
            } elseif (str_starts_with($result, 'CHAR')) {
                $result = "CHAR({$options['length']})";
            }
        }

        // Aplicar precisión y escala para tipos decimales
        if (isset($options['precision'], $options['scale'])) {
            if (in_array($abstractType, ['decimal', 'float', 'double'], true)) {
                if (str_starts_with($result, 'DECIMAL')) {
                    $result = "DECIMAL({$options['precision']},{$options['scale']})";
                } elseif (str_starts_with($result, 'FLOAT')) {
                    $result = "FLOAT({$options['precision']},{$options['scale']})";
                } elseif (str_starts_with($result, 'DOUBLE')) {
                    $result = "DOUBLE({$options['precision']},{$options['scale']})";
                } elseif (str_starts_with($result, 'REAL')) {
                    $result = "REAL({$options['precision']},{$options['scale']})";
                } elseif (str_starts_with($result, 'NUMERIC')) {
                    $result = "NUMERIC({$options['precision']},{$options['scale']})";
                }
            }
        }

        // Aplicar valores para ENUM
        if ($abstractType === 'enum' && isset($options['values'])) {
            if ($driver === 'mysql') {
                $values = array_map(static fn($v) => "'{$v}'", $options['values']);
                $result = 'ENUM(' . implode(',', $values) . ')';
            } elseif ($driver === 'postgresql') {
                // Para PostgreSQL, usamos VARCHAR con CHECK constraint
                $result = 'VARCHAR(255)';
            } else {
                // SQLite usa TEXT
                $result = 'TEXT';
            }
        }

        // Aplicar valores para SET
        if ($abstractType === 'set' && isset($options['values'])) {
            if ($driver === 'mysql') {
                $values = array_map(static fn($v) => "'{$v}'", $options['values']);
                $result = 'SET(' . implode(',', $values) . ')';
            } else {
                // PostgreSQL y SQLite usan TEXT
                $result = 'TEXT';
            }
        }

        return $result;
    }

    /**
     * Verifica si un tipo abstracto soporta especificación de longitud.
     */
    private static function supportsLength(string $abstractType): bool
    {
        return in_array(
            $abstractType,
            [
                'string',
                'char',
                'binary',
            ],
            true,
        );
    }
}
