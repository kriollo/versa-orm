<?php

declare(strict_types=1);

namespace VersaORM\Traits;

use VersaORM\VersaORM;

/**
 * Trait para manejar la conexión y desconexión de VersaORM.
 */
trait VersaORMTrait
{
    protected ?VersaORM $db = null;
    protected static array $DEFAULT_CONFIG = [
        'driver' => 'mysql',
        'host' => 'localhost',
        'port' => 3306,
        'database' => '',
        'username' => '',
        'password' => ''
    ];

    /**
     * Establece la conexión con la configuración global.
     */
    public function connectORM(): void
    {
        global $config;
        $db_config = $config['DB'];
        $this->db = new VersaORM(array_merge(static::$DEFAULT_CONFIG, [
            'driver' => $db_config['DB_DRIVER'],
            'host' => $db_config['DB_HOST'],
            'port' => $db_config['DB_PORT'],
            'database' => $db_config['DB_NAME'],
            'username' => $db_config['DB_USER'],
            'password' => $db_config['DB_PASS']
        ]));
    }

    /**
     * Desconecta y limpia la instancia ORM.
     */
    public function disconnectORM(): void
    {
        if ($this->db !== null) {
            $this->db->disconnect();
            $this->db = null;
        }
    }

    /**
     * Obtiene la instancia actual de VersaORM.
     * @return VersaORM|null
     */
    public function getORM(): ?VersaORM
    {
        return $this->db;
    }
}
