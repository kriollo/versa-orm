## Relaciones entre Modelos

Las relaciones son una de las características más potentes de VersaORM, permitiendo modelar y trabajar con asociaciones entre tablas de manera intuitiva y eficiente. Simplifican enormemente el trabajo con datos relacionados, haciendo tu código más limpio y expresivo.

### El Trait `HasRelationships`: El Corazón de las Relaciones

Para que un modelo pueda tener relaciones, debe utilizar el trait `VersaORM\Traits\HasRelationships`. Este trait es el motor que impulsa toda la funcionalidad:

1.  **Provee los Métodos de Definición**: `hasOne`, `hasMany`, `belongsTo`, y `belongsToMany`. Estos métodos no ejecutan consultas por sí mismos; actúan como una **fábrica** que crea y configura un objeto de `Relación` especializado.

2.  **Habilita la Carga Perezosa (Lazy Loading)**: El trait implementa el método mágico `__get`. Cuando accedes a una propiedad que coincide con un método de relación (ej. `$user->posts`), el trait intercepta la llamada, ejecuta la consulta a través del objeto de relación y carga los resultados. Los resultados se guardan para accesos futuros, evitando consultas duplicadas.

Esta arquitectura permite una sintaxis limpia y declarativa en tus modelos.

### Contenido de esta sección
## 🗺️ Progresión Recomendada

1. **Empieza aquí**: [Tipos de Relaciones](tipos-relaciones.md)
2. **Continúa con**: [hasMany/belongsTo](hasMany-belongsTo.md)
3. **Aprende**: [Many-to-Many](many-to-many.md)
4. **Optimiza con**: [Eager Loading](eager-loading.md)
5. **Siguiente paso**: [Funcionalidades Avanzadas](../06-avanzado/README.md)

## 🚀 Próximos Pasos

Una vez que domines las relaciones:
- **Operaciones avanzadas**: [Funcionalidades Avanzadas](../06-avanzado/README.md)
- **Seguridad**: [Seguridad y Tipado](../07-seguridad-tipado/README.md)
- **Referencia completa**: [Referencia SQL](../08-referencia-sql/README.md)

## 🧭 Navegación

### ⬅️ Anterior
- [Agregaciones](../04-query-builder/agregaciones.md)

### ➡️ Siguiente
- [Operaciones Batch](../06-avanzado/operaciones-batch.md)

### 🏠 Otras Secciones
- [🏠 Inicio](../README.md)
- [📖 Introducción](../01-introduccion/README.md)
- [⚙️ Instalación](../02-instalacion/README.md)
- [🔧 Básico](../03-basico/README.md)
- [🔍 Query Builder](../04-query-builder/README.md)
- [🚀 Avanzado](../06-avanzado/README.md)
- [🔒 Seguridad](../07-seguridad-tipado/README.md)
- [📖 Referencia SQL](../08-referencia-sql/README.md)

---

**¿Listo para conectar tus datos?** → [Comienza con Tipos de Relaciones](tipos-relaciones.md) 🔗
