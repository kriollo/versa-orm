# VersaORM QA Testing Infrastructure

Sistema de testing y QA exhaustivo para VersaORM-PHP que garantiza la máxima calidad del código y posiciona al ORM como el mejor del mundo.

## 🏗️ Arquitectura

El sistema está organizado en los siguientes componentes:

```
tests/
├── bin/                    # Scripts ejecutables
│   └── qa-runner.php      # CLI principal para ejecutar QA
├── config/                # Configuraciones
│   └── qa-config.php     # Configuración principal del sistema
├── Interfaces/            # Interfaces del sistema
│   └── TestManagerInterface.php
├── Results/               # Clases de resultados
│   ├── TestResult.php
│   ├── BenchmarkResult.php
│   ├── QualityResult.php
│   └── Report.php
├── Logging/               # Sistema de logging
│   └── TestLogger.php
├── Metrics/               # Recolección de métricas
│   └── MetricsCollector.php
├── logs/                  # Archivos de log (generados)
├── metrics/               # Archivos de métricas (generados)
├── reports/               # Reportes generados
└── TestManager.php        # Gestor principal de tests
```

## 🚀 Inicio Rápido

### Ejecutar Suite Completa

```bash
php tests/bin/qa-runner.php full
```

### Ejecutar Tests Específicos

```bash
# Tests unitarios para MySQL
php tests/bin/qa-runner.php unit --engine=mysql

# Tests de integración para todos los motores
php tests/bin/qa-runner.php integration --engine=all

# Análisis de calidad
php tests/bin/qa-runner.php quality

# Benchmarks con comparaciones
php tests/bin/qa-runner.php benchmarks --compare=eloquent,doctrine
```

## 📊 Características Principales

### 1. Testing Multi-Motor
- **MySQL/MariaDB**: Tests específicos para FULLTEXT, JSON operations, storage engines
- **PostgreSQL**: Tests para arrays, JSONB, window functions, CTEs, UUID
- **SQLite**: Validación de limitaciones y workarounds

### 2. Análisis de Calidad
- **PHPStan**: Análisis estático nivel 8
- **Psalm**: Análisis de tipos y seguridad
- **PHP-CS-Fixer**: Formato de código PSR-12
- **Cargo Clippy**: Análisis del código Rust

### 3. Benchmarks Comparativos
- Operaciones CRUD con datasets de 1K a 1M registros
- Comparaciones con Eloquent, Doctrine y PDO puro
- Métricas de throughput, latencia y memoria

### 4. Sistema de Métricas
- Recolección automática de métricas de rendimiento
- Análisis de tendencias históricas
- Alertas por degradación de calidad

### 5. Reportes Avanzados
- Reportes HTML interactivos
- Exportación JSON para CI/CD
- Dashboard de métricas en tiempo real

## 🔧 Configuración

### Configuración Principal

El archivo `tests/config/qa-config.php` contiene toda la configuración del sistema:

```php
return [
    'quality_gates' => [
        'min_coverage' => 95.0,
        'max_complexity' => 10,
        'min_quality_score' => 80
    ],
    'database_engines' => [
        'mysql' => ['enabled' => true],
        'postgresql' => ['enabled' => true],
        'sqlite' => ['enabled' => true]
    ],
    // ... más configuraciones
];
```

### Variables de Entorno

```bash
# Nivel de logging
export QA_LOG_LEVEL=info

# Entorno de ejecución
export QA_ENVIRONMENT=development
```

## 📈 Métricas y Logging

### Sistema de Logging

El sistema genera logs estructurados en `tests/logs/`:

```
[2024-01-15 10:30:45.123456] [INFO] [PID:1234] Starting full test suite execution
[2024-01-15 10:30:45.234567] [INFO] [PID:1234] Running unit tests for engine: mysql
```

### Métricas

Las métricas se almacenan en formato JSONL en `tests/metrics/`:

```json
{"type":"execution_time","data":{"operation":"unit_tests_mysql","time_seconds":12.34},"recorded_at":"2024-01-15 10:30:45.123456"}
```

## 🎯 Quality Gates

El sistema implementa gates de calidad estrictos:

- **Cobertura de Código**: Mínimo 95%
- **Complejidad Ciclomática**: Máximo 10
- **Puntuación de Calidad**: Mínimo 80/100
- **Fallos de Tests**: 0 tolerados
- **Issues de Seguridad**: 0 tolerados

## 🔍 Análisis de Calidad

### PHPStan (Nivel 8)
```bash
vendor/bin/phpstan analyse src --level=8
```

### Psalm con Seguridad
```bash
vendor/bin/psalm --no-cache --show-info=true
```

### PHP-CS-Fixer
```bash
vendor/bin/php-cs-fixer fix --dry-run --diff
```

## 🏃‍♂️ Benchmarks

### Tipos de Benchmarks

1. **CRUD Operations**: Create, Read, Update, Delete
2. **Relationship Loading**: Eager, Lazy, N+1 detection
3. **Batch Operations**: Bulk inserts, updates
4. **Memory Usage**: Peak memory, memory leaks
5. **Query Generation**: Efficiency, optimization

### Datasets de Prueba

- 1,000 registros (pequeño)
- 10,000 registros (mediano)
- 100,000 registros (grande)
- 1,000,000 registros (muy grande)

## 📊 Reportes

### Formato JSON
```json
{
  "report_id": "report_123456",
  "version": "1.0.0",
  "executive_summary": {
    "overall_status": "success",
    "total_tests": 1250,
    "success_rate": 100.0,
    "quality_score": 95
  }
}
```

### Formato HTML
Los reportes HTML incluyen:
- Gráficos interactivos
- Métricas visuales
- Tendencias históricas
- Recomendaciones de mejora

## 🚨 Alertas

El sistema genera alertas automáticas para:

- **Fallos de Tests**: Inmediato
- **Degradación de Rendimiento**: >20%
- **Caída de Calidad**: >10 puntos
- **Aumento de Memoria**: >50%

## 🔄 Integración CI/CD

### GitHub Actions

```yaml
name: QA Suite
on: [push, pull_request]
jobs:
  qa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run QA Suite
        run: php tests/bin/qa-runner.php full
```

### Códigos de Salida

- `0`: Éxito completo
- `1`: Fallos en tests o errores
- `2`: Fallos críticos

## 🛠️ Desarrollo

### Agregar Nuevos Tests

1. Crear test en el directorio apropiado
2. Seguir convenciones de nomenclatura
3. Incluir documentación
4. Verificar cobertura

### Agregar Nuevas Métricas

```php
$metricsCollector->recordCustomMetric('my_metric', [
    'value' => 123,
    'context' => 'test_execution'
]);
```

### Extender Reportes

Los reportes son extensibles mediante el sistema de plugins (implementación futura).

## 📚 Documentación Adicional

- [Guía de Contribución](../docs/contributor-guide/)
- [Arquitectura del Sistema](../docs/dev/)
- [Troubleshooting](../docs/user-guide/)

## 🤝 Contribuir

1. Fork el repositorio
2. Crear rama feature
3. Ejecutar suite de QA
4. Enviar Pull Request

## 📄 Licencia

MIT License - Ver archivo LICENSE para detalles.

---

**VersaORM QA System** - Garantizando la excelencia en cada línea de código.
