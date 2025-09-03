# Configuración de Validación Solo con Mago

## 🎯 Configuración Actualizada

Se ha configurado el sistema para usar **SOLO Mago** en la validación de Git hooks, eliminando PHP-CS-Fixer de la validación automática.

## 📋 Cambios Realizados

### 1. Hook Pre-commit (`.git/hooks/pre-commit`)
- ✅ **Solo valida con Mago** antes de cada commit
- ✅ Detecta archivos PHP staged automáticamente
- ✅ Bloquea commits si hay problemas de formato
- ✅ Funciona en Windows y Linux/macOS

### 2. Hook Pre-push (`.git/hooks/pre-push`)
- ✅ **Solo valida con Mago** antes de cada push
- ✅ Validación final en todo el proyecto
- ✅ Previene pushes con formato incorrecto

### 3. Scripts Composer Actualizados
```bash
composer mago-fmt      # Aplica formato con Mago
composer mago-check    # Valida formato con Mago (solo lectura)
```

## 🚀 Comandos Disponibles

### Para Corregir Formato
```bash
# Opción 1: Solo Mago
mago fmt

# Opción 2: Via Composer
composer mago-fmt

# Opción 3: Directorios específicos
mago fmt src/ example/ testMysql/ testPostgreSQL/ testSQLite/ tests/
```

### Para Validar Formato (Solo Lectura)
```bash
# Opción 1: Solo Mago
mago fmt --check

# Opción 2: Via Composer
composer mago-check
```

## 🔧 Flujo de Trabajo

### Antes del Commit
```bash
# 1. El hook pre-commit se ejecuta automáticamente
# 2. Si hay problemas, el commit se bloquea
# 3. Corregir con: composer mago-fmt
# 4. Agregar cambios: git add .
# 5. Intentar commit nuevamente: git commit
```

### Antes del Push
```bash
# 1. El hook pre-push valida todo el proyecto
# 2. Si hay problemas, el push se bloquea
# 3. Corregir con: composer mago-fmt
# 4. Hacer commit: git commit -m "style: formato corregido"
# 5. Intentar push nuevamente: git push
```

## ⚡ Ventajas de Solo Usar Mago

1. **Más Rápido**: Solo una herramienta de validación
2. **Más Simple**: Un solo estilo de formato consistente
3. **Menos Conflictos**: Sin diferencias entre herramientas
4. **Mejor Performance**: Validación más eficiente

## 🎯 Estado Actual

- ✅ **PHP-CS-Fixer**: Disponible pero NO se ejecuta automáticamente
- ✅ **Mago**: Configurado como validador principal en Git hooks
- ✅ **Scripts Coordinados**: Aún disponibles para uso manual (`composer format`)
- ✅ **Hooks Activos**: Solo validan con Mago

## 📝 Nota Importante

Si necesitas usar PHP-CS-Fixer ocasionalmente, puedes ejecutarlo manualmente:
```bash
composer php-cs-fix      # Aplicar PHP-CS-Fixer
composer php-cs-check    # Validar con PHP-CS-Fixer
composer format          # Aplicar ambos (coordinated)
```

Pero los **Git hooks solo validarán Mago**, no PHP-CS-Fixer.
