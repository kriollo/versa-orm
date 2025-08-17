# 🔧 Operaciones CRUD Básicas

Esta sección cubre las operaciones fundamentales de base de datos usando VersaORM: **C**reate (Crear), **R**ead (Leer), **U**pdate (Actualizar) y **D**elete (Eliminar). Son la base de cualquier aplicación que trabaje con datos.

## 📋 Contenido de esta sección

### [📝 CRUD Básico](crud-basico.md)
Las cuatro operaciones fundamentales con ejemplos prácticos
- Create: Crear nuevos registros
- Read: Consultar datos existentes
- Update: Modificar registros
- Delete: Eliminar datos
- Comparaciones con SQL tradicional

### [🏗️ VersaModel](versamodel.md)
Los métodos principales del modelo VersaORM
- `dispense()` - Crear nuevas instancias
- `load()` - Cargar registros existentes
- `store()` - Guardar cambios
- `trash()` - Eliminar registros
- Qué devuelve cada método

### [⚠️ Manejo de Errores](manejo-errores.md)
Gestión de excepciones y errores comunes
- `VersaORMException` y sus tipos
- Try-catch en operaciones CRUD
- Errores comunes y soluciones
- Debugging y logging

## ✅ Prerrequisitos

Antes de continuar, asegúrate de haber completado:
- ✅ [Instalación y Configuración](../02-instalacion/README.md)
- ✅ Tener una base de datos configurada y funcionando
- ✅ Haber probado el [Primer Ejemplo](../02-instalacion/primer-ejemplo.md)

## 🎯 Objetivos de Aprendizaje

Al completar esta sección, sabrás:
- ✅ Realizar las 4 operaciones CRUD básicas
- ✅ Usar los métodos principales de VersaModel
- ✅ Manejar errores y excepciones correctamente
- ✅ Entender qué devuelve cada operación
- ✅ Comparar VersaORM con SQL tradicional

## ⏱️ Tiempo Estimado

- **CRUD Básico**: 20-30 minutos
- **VersaModel**: 15-25 minutos
- **Manejo de Errores**: 10-15 minutos
- **Total**: 45-70 minutos

## 🗺️ Progresión Recomendada

1. **Empieza aquí**: [CRUD Básico](crud-basico.md)
2. **Profundiza con**: [VersaModel](versamodel.md)
3. **Finaliza con**: [Manejo de Errores](manejo-errores.md)
4. **Siguiente paso**: [Query Builder](../04-query-builder/README.md)

## 💡 Conceptos Clave

- **VersaModel**: La clase base para trabajar con registros
- **dispense**: Crear una nueva instancia (no guardada aún)
- **load**: Cargar un registro existente por ID
- **store**: Guardar cambios en la base de datos
- **trash**: Eliminar un registro permanentemente

## 🔧 Configuración de Ejemplos

Los ejemplos usan tablas estándar. Configura tu entorno:

```bash
php docs/setup/setup_database.php
```

## 🚀 Próximos Pasos

Una vez que domines las operaciones CRUD básicas:
- **Consultas complejas**: [Query Builder](../04-query-builder/README.md)
- **Múltiples tablas**: [Relaciones](../05-relaciones/README.md)
- **Funcionalidades avanzadas**: [Avanzado](../06-avanzado/README.md)

## 🧭 Navegación

### ⬅️ Anterior
- [Primer Ejemplo](../02-instalacion/primer-ejemplo.md)

### ➡️ Siguiente
- [Consultas Simples](../04-query-builder/consultas-simples.md)

### 🏠 Otras Secciones
- [🏠 Inicio](../README.md)
- [📖 Introducción](../01-introduccion/README.md)
- [⚙️ Instalación](../02-instalacion/README.md)
- [🔍 Query Builder](../04-query-builder/README.md)
- [🔗 Relaciones](../05-relaciones/README.md)
- [🚀 Avanzado](../06-avanzado/README.md)
- [🔒 Seguridad](../07-seguridad-tipado/README.md)
- [📖 Referencia SQL](../08-referencia-sql/README.md)

---

**¿Listo para las operaciones básicas?** → [Comienza con CRUD Básico](crud-basico.md) 📝
