<?php

declare(strict_types=1);

namespace VersaORM\Tests\Compatibility;

use DateTime;
use Exception;
use VersaORM\VersaORM;

use function array_key_exists;
use function count;
use function function_exists;
use function in_array;
use function ini_get;
use function strlen;

use const PHP_INT_SIZE;
use const PHP_SAPI;
use const PHP_VERSION_ID;

/**
 * PHPVersionDetector - Detecta automáticamente la verP y sus características.
 *
 * Esta clase proporciona métodos para detectar la versión de PHP actual,
 * sus características específicas y generar reportes de compatibilidad.
 */
class PHPVersionDetector
{
    public static array $supportedVersions = [
        '7.4' => [
            'min_version_id' => 70400,
            'features' => [
                'typed_properties',
                'arrow_functions',
                'null_coalescing_assignment',
                'array_spread',
                'numeric_literal_separator',
            ],
            'status' => 'supported',
            'eol_date' => '2022-11-28',
        ],
        '8.0' => [
            'min_version_id' => 80000,
            'features' => [
                'named_arguments',
                'attributes',
                'constructor_promotion',
                'union_types',
                'match_expression',
                'nullsafe_operator',
                'str_contains',
                'str_starts_with',
                'str_ends_with',
            ],
            'status' => 'supported',
            'eol_date' => '2023-11-26',
        ],
        '8.1' => [
            'min_version_id' => 80100,
            'features' => [
                'enums',
                'readonly_properties',
                'intersection_types',
                'first_class_callables',
                'new_in_initializers',
                'pure_intersection_types',
                'never_return_type',
                'final_class_constants',
            ],
            'status' => 'supported',
            'eol_date' => '2024-11-25',
        ],
        '8.2' => [
            'min_version_id' => 80200,
            'features' => [
                'readonly_classes',
                'dnf_types',
                'constants_in_traits',
                'deprecate_dynamic_properties',
                'allow_null_false_true_standalone_types',
                'random_extension',
            ],
            'status' => 'supported',
            'eol_date' => '2025-12-08',
        ],
        '8.3' => [
            'min_version_id' => 80300,
            'features' => [
                'typed_class_constants',
                'dynamic_class_constant_fetch',
                'override_attribute',
                'json_validate',
                'anonymous_readonly_classes',
                'negative_indices_array_access',
            ],
            'status' => 'supported',
            'eol_date' => '2026-11-23',
        ],
    ];

    /**
     * Detecta la versión PHP actual.
     */
    public static function getCurrentVersion(): array
    {
        return [
            'full_version' => PHP_VERSION,
            'major' => PHP_MAJOR_VERSION,
            'minor' => PHP_MINOR_VERSION,
            'release' => PHP_RELEASE_VERSION,
            'version_id' => PHP_VERSION_ID,
            'short_version' => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
            'extra' => PHP_EXTRA_VERSION ?? '',
            'sapi' => PHP_SAPI,
            'zts' => PHP_ZTS,
            'debug' => PHP_DEBUG,
            'os' => PHP_OS_FAMILY,
        ];
    }

    /**
     * Verifica si la versión actual está soportada.
     */
    public static function isCurrentVersionSupported(): bool
    {
        $currentVersion = self::getCurrentVersion()['short_version'];

        return array_key_exists($currentVersion, self::$supportedVersions);
    }

    /**
     * Obtiene información de soporte para la versión actual.
     */
    public static function getCurrentVersionSupport(): ?array
    {
        $currentVersion = self::getCurrentVersion()['short_version'];

        return self::$supportedVersions[$currentVersion] ?? null;
    }

    /**
     * Detecta características disponibles en la versión actual.
     */
    public static function detectAvailableFeatures(): array
    {
        $currentVersionId = PHP_VERSION_ID;
        $availableFeatures = [];

        foreach (self::$supportedVersions as $info) {
            if ($currentVersionId >= $info['min_version_id']) {
                $availableFeatures = array_merge($availableFeatures, $info['features']);
            }
        }

        return array_unique($availableFeatures);
    }

    /**
     * Verifica si una característica específica está disponible.
     */
    public static function hasFeature(string $feature): bool
    {
        return in_array($feature, self::detectAvailableFeatures(), true);
    }

    /**
     * Obtiene todas las versiones soportadas.
     */
    public static function getSupportedVersions(): array
    {
        return array_keys(self::$supportedVersions);
    }

    /**
     * Verifica si una versión específica está soportada.
     */
    public static function isVersionSupported(string $version): bool
    {
        return array_key_exists($version, self::$supportedVersions);
    }

    /**
     * Compara versiones PHP.
     */
    public static function compareVersions(string $version1, string $version2): int
    {
        return version_compare($version1, $version2);
    }

    /**
     * Verifica si la versión actual es al menos la especificada.
     */
    public static function isAtLeast(string $minVersion): bool
    {
        return version_compare(PHP_VERSION, $minVersion, '>=');
    }

    /**
     * Verifica si la versión actual es menor que la especificada.
     */
    public static function isLessThan(string $maxVersion): bool
    {
        return version_compare(PHP_VERSION, $maxVersion, '<');
    }

    /**
     * Obtiene información de extensiones PHP relevantes.
     */
    public static function getRelevantExtensions(): array
    {
        $relevantExtensions = [
            'pdo', 'pdo_mysql', 'pdo_pgsql', 'pdo_sqlite',
            'json', 'mbstring', 'openssl', 'curl',
            'zip', 'xml', 'dom', 'simplexml',
            'reflection', 'spl', 'pcre', 'hash',
            'filter', 'ctype', 'tokenizer',
        ];

        $loadedExtensions = get_loaded_extensions();
        $extensionStatus = [];

        foreach ($relevantExtensions as $extension) {
            // Check both lowercase and uppercase versions for case-insensitive matching
            $isLoaded = in_array($extension, $loadedExtensions, true)
                       || in_array(strtoupper($extension), $loadedExtensions, true)
                       || in_array(ucfirst($extension), $loadedExtensions, true);

            $extensionStatus[$extension] = [
                'loaded' => $isLoaded,
                'version' => $isLoaded ? phpversion($extension) : null,
            ];
        }

        return $extensionStatus;
    }

    /**
     * Obtiene configuración PHP relevante.
     */
    public static function getRelevantConfiguration(): array
    {
        return [
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
            'error_reporting' => ini_get('error_reporting'),
            'display_errors' => ini_get('display_errors'),
            'log_errors' => ini_get('log_errors'),
            'upload_max_filesize' => ini_get('upload_max_filesize'),
            'post_max_size' => ini_get('post_max_size'),
            'max_input_vars' => ini_get('max_input_vars'),
            'default_charset' => ini_get('default_charset'),
            'mbstring.internal_encoding' => ini_get('mbstring.internal_encoding'),
            'date.timezone' => ini_get('date.timezone'),
            'opcache.enable' => ini_get('opcache.enable'),
            'opcache.enable_cli' => ini_get('opcache.enable_cli'),
        ];
    }

    /**
     * Obtiene información de OPcache si está disponible.
     */
    public static function getOpcacheInfo(): ?array
    {
        if (!function_exists('opcache_get_status')) {
            return null;
        }

        $status = opcache_get_status(false);

        if ($status === [] || $status === false) {
            return null;
        }

        return [
            'enabled' => $status['opcache_enabled'] ?? false,
            'cache_full' => $status['cache_full'] ?? false,
            'restart_pending' => $status['restart_pending'] ?? false,
            'restart_in_progress' => $status['restart_in_progress'] ?? false,
            'memory_usage' => $status['memory_usage'] ?? [],
            'opcache_statistics' => $status['opcache_statistics'] ?? [],
        ];
    }

    /**
     * Genera reporte completo de compatibilidad.
     */
    public static function generateCompatibilityReport(): array
    {
        $currentVersion = self::getCurrentVersion();
        $support = self::getCurrentVersionSupport();

        return [
            'timestamp' => date('c'),
            'php_version' => $currentVersion,
            'support_info' => $support,
            'is_supported' => self::isCurrentVersionSupported(),
            'available_features' => self::detectAvailableFeatures(),
            'extensions' => self::getRelevantExtensions(),
            'configuration' => self::getRelevantConfiguration(),
            'opcache' => self::getOpcacheInfo(),
            'system_info' => [
                'os' => PHP_OS_FAMILY,
                'architecture' => php_uname('m'),
                'hostname' => php_uname('n'),
                'kernel' => php_uname('r'),
            ],
            'limits' => [
                'int_max' => PHP_INT_MAX,
                'int_min' => PHP_INT_MIN,
                'int_size' => PHP_INT_SIZE,
                'float_max' => PHP_FLOAT_MAX,
                'float_min' => PHP_FLOAT_MIN,
                'float_dig' => PHP_FLOAT_DIG,
                'float_epsilon' => PHP_FLOAT_EPSILON,
            ],
            'recommendations' => self::generateRecommendations($currentVersion, $support),
        ];
    }

    /**
     * Ejecuta tests de compatibilidad específicos para la versión.
     */
    public static function runCompatibilityTests(): array
    {
        $results = [];
        $currentVersion = self::getCurrentVersion();

        // Test básico de instanciación
        try {
            $config = ['driver' => 'sqlite', 'database' => ':memory:'];
            $orm = new VersaORM($config);
            $results['basic_instantiation'] = [
                'status' => 'pass',
                'message' => 'VersaORM instantiation successful',
            ];
        } catch (Exception $e) {
            $results['basic_instantiation'] = [
                'status' => 'fail',
                'message' => 'VersaORM instantiation failed: ' . $e->getMessage(),
            ];
        }

        // Test de características específicas de versión
        $features = self::detectAvailableFeatures();

        foreach ($features as $feature) {
            $results["feature_{$feature}"] = [
                'status' => 'pass',
                'message' => "Feature {$feature} is available",
            ];
        }

        // Test de extensiones requeridas
        $extensions = self::getRelevantExtensions();

        foreach (['pdo', 'json', 'mbstring'] as $required) {
            if (!$extensions[$required]['loaded']) {
                $results["extension_{$required}"] = [
                    'status' => 'fail',
                    'message' => "Required extension {$required} is not loaded",
                ];
            } else {
                $results["extension_{$required}"] = [
                    'status' => 'pass',
                    'message' => "Extension {$required} is loaded (version: {$extensions[$required]['version']})",
                ];
            }
        }

        return [
            'php_version' => $currentVersion['full_version'],
            'test_results' => $results,
            'summary' => [
                'total_tests' => count($results),
                'passed' => count(array_filter($results, static fn ($r): bool => $r['status'] === 'pass')),
                'failed' => count(array_filter($results, static fn ($r): bool => $r['status'] === 'fail')),
            ],
            'timestamp' => date('c'),
        ];
    }

    /**
     * Genera recomendaciones basadas en la versión PHP.
     */
    private static function generateRecommendations(array $version, ?array $support): array
    {
        $recommendations = [];

        if ($support === null || $support === []) {
            $recommendations[] = [
                'type' => 'error',
                'message' => "PHP version {$version['full_version']} is not supported by VersaORM",
            ];

            return $recommendations;
        }

        // Verificar si la versión está cerca del EOL
        if (isset($support['eol_date'])) {
            $eolDate = new DateTime($support['eol_date']);
            $now = new DateTime();
            $diff = $now->diff($eolDate);

            if ($eolDate < $now) {
                $recommendations[] = [
                    'type' => 'warning',
                    'message' => "PHP {$version['short_version']} reached end-of-life on {$support['eol_date']}. Consider upgrading.",
                ];
            } elseif ($diff->days < 365) {
                $recommendations[] = [
                    'type' => 'info',
                    'message' => "PHP {$version['short_version']} will reach end-of-life on {$support['eol_date']} ({$diff->days} days remaining).",
                ];
            }
        }

        // Verificar extensiones faltantes
        $extensions = self::getRelevantExtensions();
        $missingExtensions = array_filter($extensions, static fn ($ext): bool => !$ext['loaded']);

        if ($missingExtensions !== []) {
            $recommendations[] = [
                'type' => 'warning',
                'message' => 'Missing recommended extensions: ' . implode(', ', array_keys($missingExtensions)),
            ];
        }

        // Verificar configuración
        $config = self::getRelevantConfiguration();

        if ($config['memory_limit'] !== '-1' && self::parseMemoryLimit($config['memory_limit']) < 128 * 1024 * 1024) {
            $recommendations[] = [
                'type' => 'warning',
                'message' => 'Memory limit is low (' . $config['memory_limit'] . '). Consider increasing to at least 128M.',
            ];
        }

        if (!$config['opcache.enable'] || !$config['opcache.enable_cli']) {
            $recommendations[] = [
                'type' => 'info',
                'message' => 'OPcache is not enabled. Enabling it can improve performance.',
            ];
        }

        return $recommendations;
    }

    /**
     * Convierte memory_limit a bytes.
     */
    private static function parseMemoryLimit(string $limit): int
    {
        if ($limit === '-1') {
            return PHP_INT_MAX;
        }

        $limit = trim($limit);
        $last = strtolower($limit[strlen($limit) - 1]);
        $value = (int) $limit;

        switch ($last) {
            case 'g':
                $value *= 1024;
                // no break
            case 'm':
                $value *= 1024;
                // no break
            case 'k':
                $value *= 1024;
        }

        return $value;
    }
}
