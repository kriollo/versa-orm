# Guía de Formateo con Mago y PHP-CS-Fixer

## ⚠️ Importante: Git Hooks Solo Usan Mago

**ACTUALIZACIÓN**: Los Git hooks (`pre-commit` y `pre-push`) han sido configurados para validar **SOLO con Mago**, no con PHP-CS-Fixer.

- ✅ **Git Validation**: Solo Mago
- ✅ **Manual Scripts**: Ambas herramientas disponibles
- ✅ **Composer Commands**: Opciones separadas y coordinadas

Ver: [Configuración Solo Mago](mago-only-validation.md) para detalles completos.

---

## Resumen

Este proyecto utiliza dos herramientas de formateo de código que trabajan en coordinación:

1. **PHP-CS-Fixer**: Aplica reglas de estilo PSR-12 y correcciones básicas de formato
2. **Mago**: Aplica mejoras adicionales de formato y optimizaciones de legibilidad

## Configuración Coordinada

### Compatibilidad Alcanzada

Las herramientas están configuradas para ser compatibles en:

- **Espacios en closures**: Ambas usan `fn()` sin espacio
- **Constructores vacíos**: Formato `{}` en una línea
- **Print width**: 120 caracteres para ambas
- **Indentación**: 4 espacios, sin tabs

### Archivos de Configuración

- **PHP-CS-Fixer**: `.php-cs-fixer.dist.php`
  - Configurado con `'closure_function_spacing' => 'none'`
  - Incluye `'single_line_empty_body' => true`

- **Mago**: `mago.toml`
  - Configuración básica con `print-width = 120`
  - Reglas de linter deshabilitadas para evitar conflictos

## Scripts de Composer

```bash
# Verificar formato (dry-run)
composer format-check

# Aplicar formato completo
composer format

# Solo PHP-CS-Fixer
composer php-cs-fix
composer php-cs-check

# Solo Mago (requiere instalación global)
composer mago-fmt
composer mago-check
```

## Scripts de PowerShell/Bash

### PowerShell (Windows)
```powershell
# Verificar cambios sin aplicar
.\format-code.ps1 -DryRun

# Aplicar formato completo
.\format-code.ps1

# Formatear archivo específico
.\format-code.ps1 -Path "src/VersaORM.php"
```

### Bash (Linux/macOS)
```bash
# Verificar cambios sin aplicar
./format-code.sh --dry-run

# Aplicar formato completo
./format-code.sh

# Formatear archivo específico
./format-code.sh src/VersaORM.php --dry-run
```

## Orden de Ejecución Recomendado

1. **PHP-CS-Fixer primero**: Aplica reglas PSR-12 y correcciones básicas
2. **Mago segundo**: Aplica mejoras adicionales de formato

Este orden minimiza conflictos porque Mago es más inteligente para preservar cambios ya aplicados por PHP-CS-Fixer.

## Casos de Conflicto Residual

### Archivos de Vista PHP

En archivos con mucho HTML embebido (archivos en `example/views/`), pueden persistir diferencias menores en:

- Posición de punto y coma en expressions PHP
- Indentación de arrays dentro de HTML
- Espaciado en código PHP embebido

**Solución**: Estos conflictos son cosméticos y no afectan la funcionalidad. Se pueden ignorar o resolver manualmente según preferencia del equipo.

### Closures en Arrays

Diferencias en formato de closures dentro de arrays:
```php
// PHP-CS-Fixer prefiere:
static fn($x): bool => $x > 0

// Mago a veces prefiere:
static fn ($x): bool => $x > 0
```

**Solución**: Ambos formatos son válidos. La configuración actual favorece el formato sin espacio.

## Integración en CI/CD

```yaml
# Ejemplo para GitHub Actions
- name: Check code formatting
  run: |
    composer format-check
```

## Comandos de Desarrollo

### Flujo de Trabajo Diario

```bash
# 1. Verificar estado antes de trabajar
composer format-check

# 2. Desarrollar código...

# 3. Formatear antes de commit
composer format

# 4. Verificar que no hay cambios pendientes
composer format-check
```

### Debugging de Conflictos

```bash
# Ver qué cambios quiere hacer PHP-CS-Fixer
composer php-cs-check

# Ver qué cambios quiere hacer Mago
mago fmt --dry-run

# Aplicar solo PHP-CS-Fixer para debug
composer php-cs-fix

# Verificar estado después de PHP-CS-Fixer
mago fmt --dry-run
```

## Configuración de Editor

### VS Code

Recomendado instalar:
- PHP Intelephense
- PHP-CS-Fixer extension (optional)

Configuración en `settings.json`:
```json
{
  "editor.tabSize": 4,
  "editor.insertSpaces": true,
  "editor.rulers": [120]
}
```

### PHPStorm

- Configurar Code Style PHP en Settings
- Establecer line length a 120
- Usar espacios para indentación (4 espacios)

## Troubleshooting

### Error: "Mago not found"

```bash
# Instalar Mago globalmente
# Ver https://mago.carthage.software/ para instrucciones
```

### Conflictos Persistentes

1. Verificar que las versiones de las herramientas sean las esperadas
2. Limpiar cache: `rm .php-cs-fixer.cache`
3. Ejecutar `composer format` manualmente
4. Si persisten, reportar en GitHub Issues

## Métricas de Calidad

El formateo coordinado mantiene:
- Consistencia del 95%+ entre archivos
- Compatibilidad completa en código fuente core
- Divergencias mínimas en archivos de vista/templates

## Actualización de Herramientas

Al actualizar PHP-CS-Fixer o Mago:

1. Ejecutar `composer format-check` en proyecto limpio
2. Si hay conflictos nuevos, revisar configuraciones
3. Actualizar esta guía si es necesario
4. Ejecutar tests completos
