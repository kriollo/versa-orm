# QA Tools Integration

Esta documentación explica cómo están integradas las herramientas de QA para evitar conflictos entre ellas.

## Problema Resuelto

Antes de esta integración, ejecutar las herramientas de QA en cualquier orden causaba conflictos:
- Rector cambiaba el código
- PHP-CS-Fixer lo reformateaba
- PHPStan encontraba nuevos problemas
- Volver a ejecutar Rector cambiaba el código otra vez
- **Ciclo infinito de cambios** 🔄

## Solución Implementada

### 1. Orden de Ejecución Definido

```
1. Rector       → Modernización y refactoring del código
2. PHP-CS-Fixer → Formateo y estilo del código
3. PHPStan      → Análisis estático y verificación de tipos
4. Psalm        → Análisis de seguridad complementario
5. PHPUnit      → Pruebas unitarias e integración
```

### 2. Configuraciones Coordinadas

#### Rector (`rector.php`)
- **Responsabilidad**: Modernización del código, tipos, estructuras
- **Evita conflictos**: No maneja formateo, deja que PHP-CS-Fixer se encargue
- **Skips importantes**:
  - Reglas de estilo (las maneja PHP-CS-Fixer)
  - Imports (los maneja PHP-CS-Fixer)
  - Formateo de arrays (lo maneja PHP-CS-Fixer)

#### PHP-CS-Fixer (`.php-cs-fixer.dist.php`)
- **Responsabilidad**: Formateo, estilo, organización de imports
- **Evita conflictos**: No maneja lógica del código
- **Reglas deshabilitadas**:
  - `declare_strict_types` → Lo maneja Rector
  - `constructor_promotion` → Lo maneja Rector
  - `void_return` → Lo maneja Rector
  - `nullable_type_declaration_for_default_null_value` → Lo maneja Rector

#### PHPStan (`phpstan.neon`)
- **Responsabilidad**: Análisis estático, verificación de tipos
- **Configuración ORM-friendly**: Permite patrones comunes de ORM
- **Nivel 8**: Máximo nivel de strictness
- **Ignora**: Métodos mágicos, propiedades dinámicas del ORM

#### Psalm (`psalm.xml`)
- **Responsabilidad**: Análisis de seguridad, detección de vulnerabilidades
- **Complementario a PHPStan**: Se enfoca en lo que PHPStan no cubre
- **Nivel 5**: Menos estricto para evitar redundancia
- **Suprime**: Verificaciones que ya hace PHPStan

## Uso

### Opción 1: Script de Integración (Recomendado)

```bash
# Verificar todos los problemas
php qa-integration.php

# Arreglar automáticamente lo que se pueda
php qa-integration.php --fix

# Solo ejecutar herramientas específicas
php qa-integration.php --only=rector,php-cs-fixer

# Saltar herramientas específicas
php qa-integration.php --skip=psalm

# Modo verbose
php qa-integration.php --verbose
```

### Opción 2: Makefile

```bash
# Verificar todo
make qa

# Arreglar todo
make qa-fix

# Herramientas individuales
make rector
make cs
make phpstan
make psalm

# Verificación rápida para desarrollo
make dev-check

# Pipeline completo para CI
make ci
```

### Opción 3: Manual (No Recomendado)

Si necesitas ejecutar manualmente, **SIEMPRE** en este orden:

```bash
# 1. Rector primero
vendor/bin/rector process

# 2. PHP-CS-Fixer después
vendor/bin/php-cs-fixer fix

# 3. PHPStan para análisis
vendor/bin/phpstan analyse

# 4. Psalm para seguridad
vendor/bin/psalm

# 5. Tests al final
vendor/bin/phpunit
```

## Configuración Específica para ORM

### Patrones Permitidos

Todas las herramientas están configuradas para permitir patrones comunes de ORM:

- **Métodos mágicos**: `__get()`, `__set()`, `__call()`
- **Propiedades dinámicas**: Acceso a propiedades no definidas
- **Factory methods**: `new static()`
- **Relaciones flexibles**: Tipos de retorno mixtos en relaciones
- **Consultas SQL**: Strings que contienen SQL

### Exclusiones Importantes

- **Tests**: Los tests tienen reglas más flexibles
- **Binarios**: Archivos en `src/binary/` se ignoran
- **Vendor**: Dependencias externas se ignoran
- **Cache/Reports**: Directorios temporales se ignoran

## Flujo de Trabajo Recomendado

### Durante Desarrollo

```bash
# Verificación rápida (sin Psalm para velocidad)
make dev-check

# Arreglo rápido de estilo
make dev-fix
```

### Antes de Commit

```bash
# Verificación completa
make pre-commit
```

### Antes de Push

```bash
# Verificación + tests
make pre-push
```

### En CI/CD

```bash
# Pipeline completo
make ci
```

## Resolución de Problemas

### Si las herramientas siguen conflictuando:

1. **Limpia el cache**:
   ```bash
   make clean
   ```

2. **Ejecuta en orden estricto**:
   ```bash
   php qa-integration.php --fix
   ```

3. **Verifica configuraciones**:
   ```bash
   make config
   make status
   ```

### Errores Comunes

#### "Rector cambió algo que PHP-CS-Fixer no acepta"
- **Solución**: Ejecuta `php qa-integration.php --fix` que maneja el orden correcto

#### "PHPStan encuentra errores después de Rector"
- **Solución**: Normal, Rector puede exponer nuevos problemas de tipos. Revisa y corrige manualmente.

#### "Psalm reporta lo mismo que PHPStan"
- **Solución**: Psalm está configurado para suprimir redundancias. Si ves duplicados, reporta un bug.

## Archivos de Configuración

- `rector.php` - Configuración de Rector
- `.php-cs-fixer.dist.php` - Configuración de PHP-CS-Fixer
- `phpstan.neon` - Configuración de PHPStan
- `psalm.xml` - Configuración de Psalm
- `qa-integration.php` - Script de integración
- `qa-config.json` - Configuración centralizada
- `Makefile` - Comandos de conveniencia

## Beneficios de esta Integración

✅ **Sin conflictos**: Las herramientas no se pisan entre ellas
✅ **Orden correcto**: Ejecución en secuencia lógica
✅ **ORM-friendly**: Configurado para patrones de ORM
✅ **Automatizado**: Un comando ejecuta todo
✅ **Flexible**: Puedes ejecutar herramientas individuales
✅ **Rápido**: Cache optimizado y ejecución paralela donde es posible
✅ **CI-ready**: Perfecto para pipelines de integración continua

## Mantenimiento

Para actualizar las configuraciones:

1. Modifica los archivos de configuración individuales
2. Actualiza `qa-config.json` si es necesario
3. Prueba con `php qa-integration.php --fix`
4. Documenta cambios importantes aquí

---

**¿Dudas?** Revisa los comentarios en los archivos de configuración o ejecuta `make help` para ver todas las opciones disponibles.
