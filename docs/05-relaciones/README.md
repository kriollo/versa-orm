
## Relaciones entre Modelos

Las relaciones en VersaORM permiten modelar asociaciones entre tablas de forma intuitiva y eficiente, con una API dual inspirada en Eloquent:

- **Acceso por propiedad**: `$user->profile` o `$task->notes` (lazy/eager loading, retorna resultados)
- **Acceso por método**: `$user->profile()` o `$task->notes()` (retorna el objeto de relación, permite encadenar QueryBuilder)

### Ejemplo rápido
```php
$user = User::findOne(1);
$bio = $user->profile->bio; // Acceso por propiedad (lazy loading)

$count = $user->posts()->where('published', true)->count(); // Encadenamiento tipo Eloquent
```

### El Trait `HasRelationships`: El Corazón de las Relaciones
> **Nota importante:** Cuando uses el método `fresh()` para recargar un modelo y sus relaciones, **debes reasignar la instancia**:
>
> ```php
> $user = $user->fresh();
> $roles = $user->roles;
> ```
> Así aseguras que accedes a los datos realmente actualizados y evitas inconsistencias por caché de relaciones.

Para que un modelo pueda tener relaciones, debe utilizar el trait `VersaORM\Traits\HasRelationships`. Este trait es el motor que impulsa toda la funcionalidad:

1.  **Provee los Métodos de Definición**: `hasOne`, `hasMany`, `belongsTo`, y `belongsToMany`. Estos métodos no ejecutan consultas por sí mismos; actúan como una **fábrica** que crea y configura un objeto de relación especializado.

2.  **API Dual de Acceso**:
	- **Propiedad**: `$modelo->relacion` ejecuta la consulta y retorna los resultados (lazy/eager loading).
	- **Método**: `$modelo->relacion()` retorna el objeto de relación, permitiendo encadenar QueryBuilder (`where`, `count`, `orderBy`, etc.).

3.  **Carga Perezosa y Eager Loading**:
	- Lazy: Acceso por propiedad ejecuta la consulta al primer acceso y cachea el resultado.
	- Eager: Usando `with()` en el QueryBuilder precargas relaciones para evitar el problema N+1.

### Ejemplo de encadenamiento QueryBuilder en relaciones
```php
$task = Task::findOne(1);
$totalNotas = $task->notes()->where('archived', false)->count();
$primerNota = $task->notes()->orderBy('created_at', 'asc')->firstArray();
```

### Ejemplo de acceso tradicional (lazy/eager loading)
```php
$user = User::findOne(1);
$profile = $user->profile; // Lazy loading
$roles = $user->roles;     // Puede ser eager si usaste with('roles')
```

### Resumen de ventajas
- Sintaxis flexible: puedes usar ambos estilos según tu necesidad.
- Compatibilidad total con tests y código legado.
- Eficiencia: eager loading con `with()` para colecciones grandes.

---
**¿Listo para conectar tus datos?** → [Comienza con Tipos de Relaciones](tipos-relaciones.md) 🔗

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
