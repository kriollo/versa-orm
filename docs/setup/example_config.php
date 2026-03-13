<?php

/**
 * Configuración básica para ejemplos de VersaORM
 *
 * Este archivo muestra cómo configurar VersaORM para usar
 * en todos los ejemplos de la documentación.
 */

require_once __DIR__.'/../../vendor/autoload.php';

use VersaORM\VersaORM;

/**
 * Función helper para inicializar VersaORM con la configuración de ejemplos
 */
function getExampleORM(): VersaORM
{
    static $orm = null;

    if ($orm === null) {
        // Cargar configuración
        $config = require __DIR__.'/database_config.php';

        try {
            $orm = new VersaORM($config);
        } catch (Exception $e) {
            exit('Error conectando a la base de datos: '.$e->getMessage()."\n");
        }
    }

    return $orm;
}

/**
 * Función helper para mostrar resultados de forma legible
 */
function showResults($data, $title = 'Resultados')
{
    echo "\n=== $title ===\n";

    if (empty($data)) {
        echo "No hay datos para mostrar.\n";

        return;
    }

    if (is_array($data)) {
        if (isset($data[0]) && is_array($data[0])) {
            // Array de arrays (múltiples registros)
            foreach ($data as $index => $row) {
                echo 'Registro '.($index + 1).":\n";
                foreach ($row as $key => $value) {
                    echo "  $key: $value\n";
                }
                echo "\n";
            }
        } else {
            // Array simple (un registro)
            foreach ($data as $key => $value) {
                echo "$key: $value\n";
            }
        }
    } else {
        // Valor simple
        echo $data."\n";
    }

    echo "=== Fin $title ===\n\n";
}

/**
 * Función helper para mostrar SQL equivalente
 */
function showSQLEquivalent($sql, $description = '')
{
    echo 'SQL Equivalente'.($description ? " ($description)" : '').":\n";
    echo "```sql\n$sql\n```\n\n";
}

/**
 * Función helper para mostrar qué devuelve un método
 */
function showReturnType($returnType, $description = '')
{
    echo "Devuelve: $returnType".($description ? " - $description" : '')."\n\n";
}
