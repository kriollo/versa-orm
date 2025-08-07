# VersaORM PostgreSQL Tests

Esta carpeta contiene la suite completa de tests para VersaORM adaptada específicamente para PostgreSQL. Los tests han sido homologados desde la suite de tests MySQL original y adaptados para aprovechar las características específicas de PostgreSQL.

## Configuración

### Requisitos
- PostgreSQL 12 o superior
- PHP 7.4 o superior
- Extensión PDO_PGSQL habilitada
- VersaORM CLI compilado con soporte PostgreSQL

### Base de Datos de Prueba
Crear una base de datos llamada `versaorm_test` en PostgreSQL:

```sql
CREATE DATABASE versaorm_test;
CREATE USER local WITH PASSWORD 'local';
GRANT ALL PRIVILEGES ON DATABASE versaorm_test TO local;
```

### Variables de Entorno (Opcional)
Puedes configurar las siguientes variables de entorno para personalizar la conexión:

```bash
export DB_DRIVER=postgresql
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=versaorm_test
export DB_USER=local
export DB_PASS=local
```

## Ejecución de Tests

### Ejecutar toda la suite PostgreSQL
```bash
composer test-postgresql
```

### Ejecutar con cobertura de código
```bash
composer test-postgresql-coverage
```

### Ejecutar tests específicos
```bash
vendor/bin/phpunit --configuration phpunit-postgresql.xml testPostgreSQL/VersaORMTest.php
```

### Ejecutar un test específico
```bash
vendor/bin/phpunit --configuration phpunit-postgresql.xml --filter testPostgreSQLSpecificFeatures testPostgreSQL/VersaORMTest.php
```

## Estructura de Tests

### Tests Base
- **TestCase.php**: Clase base con configuración PostgreSQL y esquema adaptado
- **bootstrap.php**: Configuración de autoload y conexión específica para PostgreSQL

### Tests Principales
- **VersaORMTest.php**: Tests básicos del ORM adaptados para PostgreSQL
- **QueryBuilderTest.php**: Tests del query builder con sintaxis PostgreSQL
- **VersaModelTest.php**: Tests del modelo con características específicas de PostgreSQL
- **SecurityTest.php**: Tests de seguridad con ataques específicos de PostgreSQL
- **PostgreSQLAdvancedSQLTest.php**: Tests avanzados de características específicas de PostgreSQL

## Características PostgreSQL Específicas Testeadas

### Sintaxis y Tipos de Datos
- **Parámetros numerados**: `$1`, `$2` en lugar de `?`
- **SERIAL**: Auto-incremento específico de PostgreSQL
- **TIMESTAMP**: Manejo de fechas y timestamps
- **BOOLEAN**: Tipo booleano nativo
- **ARRAY**: Soporte para arrays nativos
- **JSONB**: Soporte para JSON binario

### Funciones y Operadores
- **ILIKE**: Búsqueda case-insensitive
- **Expresiones regulares**: `~`, `~*`, `!~`
- **Operadores de array**: `@>`, `&&`, `<@`
- **Operadores JSONB**: `@>`, `?`, `?|`, `?&`
- **Window functions**: ROW_NUMBER(), LAG(), LEAD()
- **CTEs**: Common Table Expressions

### Características Avanzadas
- **Full-text search**: tsvector, tsquery, ts_rank
- **Generate series**: Generación de secuencias
- **Array functions**: unnest(), array_agg()
- **JSON path queries**: Consultas con rutas JSON
- **Savepoints**: Puntos de guardado en transacciones
- **Row Level Security**: Tests básicos de RLS

## Diferencias con MySQL

### Sintaxis
- Parámetros: `$1, $2, $3` vs `?, ?, ?`
- Auto-increment: `SERIAL` vs `AUTO_INCREMENT`
- Comentarios: `--` vs `#`
- Strings case-insensitive: `ILIKE` vs `LIKE`

### Transacciones
- `BEGIN` vs `START TRANSACTION`
- Savepoints nativos con `SAVEPOINT name`
- Rollback a savepoint: `ROLLBACK TO SAVEPOINT name`

### Esquema
- `CASCADE` en DROP TABLE por defecto
- Nombres de tablas/columnas en minúsculas por defecto
- Soporte nativo para esquemas múltiples

## Tests de Seguridad Específicos

Los tests de seguridad incluyen verificaciones para:

- **Inyección SQL específica de PostgreSQL**:
  - Funciones del sistema: `version()`, `current_user`, `pg_sleep()`
  - Lectura de archivos: `pg_read_file()`
  - Arrays maliciosos: `ARRAY[version()]`

- **Funcionalidades específicas**:
  - JSONB injection attempts
  - Array type injection
  - PostgreSQL regex injection
  - Transaction boundary attacks

## Configuración de CI/CD

Para integración continua, usar estos comandos:

```yaml
- name: Setup PostgreSQL
  run: |
    sudo systemctl start postgresql
    sudo -u postgres createdb versaorm_test
    sudo -u postgres psql -c "CREATE USER local WITH PASSWORD 'local';"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE versaorm_test TO local;"

- name: Run PostgreSQL Tests
  run: composer test-postgresql
```

## Troubleshooting

### Error de conexión
- Verificar que PostgreSQL esté ejecutándose
- Verificar credenciales en `bootstrap.php`
- Verificar que la base `versaorm_test` exista

### Tests fallando
- Verificar que el binario VersaORM CLI tenga soporte PostgreSQL
- Verificar permisos de la base de datos
- Verificar que las extensiones requeridas estén habilitadas

### Performance
Los tests pueden ser más lentos que MySQL debido a:
- Creación/eliminación de esquemas más estricta
- Validación de constraints más rigurosa
- Features avanzadas que requieren más procesamiento

## Extensiones de PostgreSQL

Algunos tests requieren extensiones específicas:
```sql
-- Para UUID
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Para full-text search avanzado
CREATE EXTENSION IF NOT EXISTS unaccent;

-- Para funciones adicionales
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

## Contribuir

Al agregar nuevos tests:
1. Usar sintaxis de PostgreSQL para parámetros (`$1`, `$2`)
2. Considerar características específicas de PostgreSQL
3. Incluir cleanup apropiado con `CASCADE`
4. Documentar cualquier extensión requerida
5. Testear tanto con como sin extensiones opcionales
