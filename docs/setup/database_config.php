<?php
/**
 * Configuración de base de datos para ejemplos de VersaORM
 *
 * Copia este archivo y modifica los valores según tu entorno.
 * Por defecto usa SQLite para simplicidad.
 */

return [
    // Configuración SQLite (por defecto)
    'driver' => 'sqlite',
    'database' => __DIR__ . '/../../docs_examples.sqlite',
    'host' => '',
    'username' => '',
    'password' => '',
    'charset' => 'utf8mb4',

    // Descomenta y modifica para MySQL
    /*
    'driver' => 'mysql',
    'host' => 'localhost',
    'database' => 'versaorm_docs',
    'username' => 'tu_usuario',
    'password' => 'tu_password',
    'charset' => 'utf8mb4',
    */

    // Descomenta y modifica para PostgreSQL
    /*
    'driver' => 'pgsql',
    'host' => 'localhost',
    'database' => 'versaorm_docs',
    'username' => 'tu_usuario',
    'password' => 'tu_password',
    'charset' => 'utf8',
    */
];
