# Tuning de MariaDB y PostgreSQL para tests locales rapidos

Esta guia esta enfocada en acelerar suites de test en tu maquina local.
No uses estos parametros en produccion sin evaluar durabilidad y recuperacion.

## Perfil recomendado para VersaORM tests

1. Ejecuta tests por TCP loopback para evitar resolucion extra o fallback a socket:

```bash
export DB_HOST=127.0.0.1
```

2. Mantiene Xdebug apagado cuando no mides cobertura:

```bash
export XDEBUG_MODE=off
```

3. Usa scripts rapidos del proyecto:

```bash
composer test-mysql-fast
composer test-postgresql-fast
```

## MariaDB (solo local/test)

Edita tu archivo de configuracion (por ejemplo `mysqld.cnf`) y agrega:

```cnf
[mysqld]
# Conexiones
bind-address = 127.0.0.1
skip-name-resolve = 1
max_connections = 100
thread_cache_size = 64

# InnoDB en modo rapido para tests
innodb_buffer_pool_size = 2G
innodb_flush_log_at_trx_commit = 2
innodb_doublewrite = 0
innodb_flush_method = O_DIRECT_NO_FSYNC

# Menos IO de logs en entorno efimero
sync_binlog = 0
skip-log-bin
performance_schema = OFF

# Memoria para tablas temporales
tmp_table_size = 128M
max_heap_table_size = 128M
```

Reinicia MariaDB y valida:

```sql
SHOW VARIABLES WHERE Variable_name IN (
  'skip_name_resolve',
  'innodb_flush_log_at_trx_commit',
  'innodb_doublewrite',
  'sync_binlog',
  'performance_schema'
);
```

## PostgreSQL (solo local/test)

Edita `postgresql.conf` y usa un perfil agresivo de tests:

```conf
# Memoria y planner
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 64MB
maintenance_work_mem = 512MB
random_page_cost = 1.1
effective_io_concurrency = 200
jit = off

# WAL/checkpoints para throughput
wal_compression = on
max_wal_size = 4GB
checkpoint_timeout = 30min
checkpoint_completion_target = 0.9

# Durabilidad relajada (test only)
fsync = off
synchronous_commit = off
full_page_writes = off

# Menos overhead de red local
listen_addresses = '127.0.0.1'
ssl = off
```

Reinicia PostgreSQL y valida:

```sql
SHOW shared_buffers;
SHOW work_mem;
SHOW fsync;
SHOW synchronous_commit;
SHOW full_page_writes;
SHOW ssl;
```

## Ajustes extra para maquinas potentes

1. Data dir en NVMe o `tmpfs` para reducir latencia de I/O.
2. Mantener DB residente en RAM con buffer pool/shared_buffers altos.
3. Evitar antivirus/indexadores sobre directorios de datos.
4. Precalentar esquema antes de benchmark (ejecutar una corrida corta).

## Seguridad y limites

1. `fsync=off` y `synchronous_commit=off` pueden perder datos ante corte de energia.
2. Usa un perfil separado de test (`postgresql-test.conf`, `mariadb-test.cnf`).
3. No mezclar este tuning con ambientes de produccion.
