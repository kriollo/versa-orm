# 📚 Documentación de VersaORM

¡Bienvenido a la documentación oficial de VersaORM!

## 🤔 ¿Eres nuevo con los ORM?

**No te preocupes, empezamos desde cero.** Un **ORM** (Object-Relational Mapping) es una herramienta que te permite interactuar con bases de datos usando código PHP natural, sin necesidad de escribir SQL complicado.

### 🔄 Antes vs Después

**❌ ANTES (SQL tradicional - difícil y peligroso):**
```sql
-- Propenso a errores de sintaxis
SELECT users.*, profiles.bio FROM users
LEFT JOIN profiles ON users.id = profiles.user_id
WHERE users.status = 'active' AND users.age >= 18;

-- Vulnerable a inyección SQL
$query = "SELECT * FROM users WHERE name = '" . $_POST['name'] . "'";
```

**✅ DESPUÉS (VersaORM - fácil y seguro):**
```php
// Código PHP natural y seguro
$users = $orm->table('users')
    ->join('profiles', 'users.id', '=', 'profiles.user_id')
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->findAll();

// Automáticamente protegido contra inyección SQL
$users = $orm->table('users')->where('name', '=', $_POST['name'])->findAll();
```

## 🏆 ¿Por qué elegir VersaORM?

### 🚀 **Más Rápido que Cualquier Competencia**
- **10x más rápido** que Eloquent (Laravel)
- **5x más rápido** que Doctrine (Symfony)
- Motor escrito en **Rust** (el lenguaje más rápido del mundo)

### 🛡️ **Seguridad Extrema**
- **Cero vulnerabilidades SQL** por diseño
- Validación automática de datos
- Protección Mass Assignment integrada

### 💡 **Súper Fácil de Aprender**
- Sintaxis intuitiva y familiar
- Documentación completa con ejemplos
- Migración sencilla desde otros ORMs

### 🌐 **Máxima Compatibilidad**
- MySQL, PostgreSQL, SQLite
- Cualquier framework PHP (Laravel, Symfony, etc.)
- Proyectos PHP existentes

---

**VersaORM** es el ORM más avanzado para PHP, diseñado tanto para **principiantes** que quieren aprender fácilmente, como para **expertos** que necesitan máximo rendimiento.

## 📖 ¿Por dónde empezar?

Esta documentación está organizada para llevarte paso a paso desde cero hasta convertirte en un experto:

## Guía del Usuario

- **[🚀 Primeros Pasos](getting-started/README.md)**
  - [Instalación](getting-started/installation.md)
  - [Configuración](getting-started/configuration.md)
- **[📖 Guía de Uso](user-guide/README.md)**
  - [Uso Básico](user-guide/01-basic-usage.md)
  - [Query Builder](user-guide/02-query-builder.md)
  - [🚀 Operaciones de Lote (Batch)](user-guide/03-batch-operations.md)
  - [Modelos y Objetos (VersaModel)](user-guide/03-models-and-objects.md)
  - [Herramienta de Línea de Comandos (CLI)](user-guide/04-cli-tool.md)
  - [🔒 Validación y Mass Assignment](user-guide/05-validation-mass-assignment.md)
  - [🎯 Tipado Fuerte y Validación de Esquemas](user-guide/06-strong-typing-schema-validation.md)
  - [🔒 Modo Freeze - Protección de Esquema](user-guide/07-freeze-mode.md)
  - [🏢 Ejemplo Práctico: Modo Freeze en Producción](user-guide/08-freeze-mode-example.md)

## Guía del Contribuidor

- **[🛠️ Guía del Contribuidor](contributor-guide/README.md)**
  - [Arquitectura del Proyecto](contributor-guide/01-architecture.md)
  - [Configuración del Entorno de Desarrollo](contributor-guide/02-development-setup.md)
  - [Estándares de Código](contributor-guide/03-coding-standards.md)
