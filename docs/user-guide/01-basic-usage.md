# 📚 Uso Básico (Operaciones CRUD)

¡Bienvenido al mundo sin SQL! Una vez que hayas [configurado VersaORM](../getting-started/configuration.md), puedes realizar todas las operaciones de base de datos usando código PHP natural.

## 🤔 ¿Por qué VersaORM es mejor que SQL?

**VersaORM** implementa el patrón **Active Record**, donde cada objeto representa una fila de tu base de datos. Esto significa que trabajas con **objetos PHP familiares** en lugar de escribir SQL complicado.

### 🔄 La Gran Diferencia

**❌ ANTES (SQL tradicional - complicado y peligroso):**
```sql
-- Propenso a errores de sintaxis
INSERT INTO users (name, email, status) VALUES ('Juan Pérez', 'juan@email.com', 'active');
SELECT * FROM users WHERE id = 1;
UPDATE users SET name = 'Juan Carlos', status = 'inactive' WHERE id = 1;
DELETE FROM users WHERE id = 1;

-- Vulnerable a inyección SQL
$sql = "SELECT * FROM users WHERE name = '" . $_POST['name'] . "'";
```

**✅ DESPUÉS (VersaORM - fácil y seguro):**
```php
// Código PHP natural y seguro
$user = VersaModel::dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan@email.com';
$user->status = 'active';
$user->store(); // ¡Listo!

$user = VersaModel::load('users', 1);
$user->name = 'Juan Carlos';
$user->status = 'inactive';
$user->store();

$user->trash(); // Eliminado

// Automáticamente protegido contra inyección SQL
$users = VersaModel::findAll('users', 'name = ?', [$_POST['name']]);
```

## ⚙️ Configuración Previa

**Asegúrate de haber configurado VersaORM** como se explica en la guía de configuración:

```php
// En tu archivo de arranque (p. ej., index.php)
use VersaORM\VersaORM;
use VersaORM\VersaModel;

$orm = new VersaORM($config);
VersaModel::setORM($orm); // ¡Importante para todos los ejemplos!
```

---

## 1. 📝 Crear Registros (Create)

### ❌ Forma Tradicional (SQL)
```php
// Complicado y propenso a errores
$stmt = $pdo->prepare(
    "INSERT INTO users (name, email, status, created_at) VALUES (?, ?, ?, NOW())"
);
$stmt->execute(['Juan Pérez', 'juan.perez@example.com', 'active']);
$userId = $pdo->lastInsertId();

echo "Usuario creado con ID: " . $userId;

// Problemas:
// ❌ SQL manual propenso a errores de sintaxis
// ❌ Tienes que manejar prepared statements manualmente
// ❌ No hay validación automática
// ❌ Tienes que obtener el ID manualmente
```

### ✅ Forma VersaORM (Súper Fácil)
```php
// Simple, seguro y automático
$user = VersaModel::dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan.perez@example.com';
$user->status = 'active';
$user->store();

echo "Usuario creado con ID: " . $user->id;

// Ventajas:
// ✅ Código PHP natural y fácil de leer
// ✅ Protección automática contra inyección SQL
// ✅ El ID se asigna automáticamente
// ✅ created_at se añade automáticamente
// ✅ Validación integrada (si usas modelos personalizados)
```

### 🔍 ¿Qué hace `store()` automáticamente?
- 🛡️ **Seguridad**: Usa prepared statements automáticamente
- 🔄 **Detección inteligente**: Sabe si es INSERT o UPDATE
- 🆔 **Auto-ID**: Asigna el ID generado al objeto
- 📅 **Timestamps**: Añade created_at/updated_at si existen
- ⚡ **Optimización**: Ejecuta solo si hay cambios

---

## 2. 🔍 Leer Registros (Read)

### ❌ Forma Tradicional (SQL)
```php
// Leer un registro por ID
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([1]);
$userData = $stmt->fetch(PDO::FETCH_ASSOC);

if ($userData) {
    echo "Nombre: " . $userData['name'];
    echo "Email: " . $userData['email'];
} else {
    echo "Usuario no encontrado.";
}

// Leer múltiples registros
$stmt = $pdo->prepare("SELECT * FROM users WHERE status = ?");
$stmt->execute(['active']);
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo "Usuarios activos: " . count($users);

// Problemas:
// ❌ Siempre trabajas con arrays, no objetos
// ❌ Tienes que escribir SQL para cada consulta
// ❌ No hay protección automática
// ❌ Código repetitivo y verbose
```

### ✅ Forma VersaORM (Súper Fácil)
```php
// Leer un registro por ID
$user = VersaModel::load('users', 1);

if ($user) {
    echo "Nombre: " . $user->name;    // Acceso como objeto
    echo "Email: " . $user->email;   // Más natural
} else {
    echo "Usuario no encontrado.";
}

// Leer múltiples registros
$activeUsers = VersaModel::findAll('users', 'status = ?', ['active']);

echo "Usuarios activos: " . count($activeUsers);

foreach ($activeUsers as $user) {
    echo $user->name . "\n"; // Cada elemento es un objeto
}

// Ventajas:
// ✅ Trabajas con objetos familiares
// ✅ Sin SQL manual
// ✅ Protección automática contra inyección SQL
// ✅ Código limpio y expresivo
```

### 🔥 Métodos de Lectura Disponibles
```php
// Cargar un registro por ID
$user = VersaModel::load('users', 1);

// Encontrar todos los registros
$users = VersaModel::findAll('users');

// Encontrar con condiciones simples
$activeUsers = VersaModel::findAll('users', 'status = ?', ['active']);

// Para consultas complejas, usa Query Builder
$users = $orm->table('users')
    ->where('age', '>=', 18)
    ->where('status', '=', 'active')
    ->orderBy('created_at', 'desc')
    ->findAll();
```

---

## 3. ✏️ Actualizar Registros (Update)

### ❌ Forma Tradicional (SQL)
```php
// Actualizar requiere múltiples pasos manuales
$stmt = $pdo->prepare("UPDATE users SET name = ?, status = ?, updated_at = NOW() WHERE id = ?");
$stmt->execute(['Juan Carlos Pérez', 'inactive', 1]);

if ($stmt->rowCount() > 0) {
    echo "Usuario actualizado.";
} else {
    echo "Usuario no encontrado o sin cambios.";
}

// Problemas:
// ❌ Tienes que escribir el SQL UPDATE manualmente
// ❌ Manejas updated_at manualmente
// ❌ No sabes qué campos cambiaron realmente
// ❌ Vulnerable a errores de sintaxis
```

### ✅ Forma VersaORM (Súper Fácil)
```php
// Actualizar es tan simple como modificar propiedades
$user = VersaModel::load('users', 1);

if ($user) {
    $user->name = 'Juan Carlos Pérez';
    $user->status = 'inactive';
    $user->store(); // ¡Eso es todo!
    
    echo "Usuario actualizado.";
}

// Ventajas:
// ✅ Código natural como asignación de variables
// ✅ updated_at se actualiza automáticamente
// ✅ Solo actualiza los campos que realmente cambiaron
// ✅ Detección inteligente de cambios
```

### 🧠 Inteligencia de `store()` para Updates
- 🔍 **Detección automática**: Sabe que es UPDATE porque ya tiene ID
- ⚡ **Solo cambios**: Actualiza únicamente los campos modificados
- 📅 **Timestamps**: Actualiza `updated_at` automáticamente
- 🛡️ **Seguridad**: Siempre usa prepared statements

---

## 4. 🗑️ Eliminar Registros (Delete)

### ❌ Forma Tradicional (SQL)
```php
// Eliminación manual con verificación
$stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
$stmt->execute([1]);

if ($stmt->rowCount() > 0) {
    echo "Usuario eliminado.";
} else {
    echo "Usuario no encontrado.";
}

// Problemas:
// ❌ SQL manual para cada eliminación
// ❌ Tienes que verificar si se eliminó algo
// ❌ No hay verificación de existencia previa
// ❌ Posibles errores de sintaxis
```

### ✅ Forma VersaORM (Súper Fácil)
```php
// Eliminación intuitiva y segura
$user = VersaModel::load('users', 1);

if ($user) {
    $user->trash(); // ¡Simple y directo!
    echo "Usuario eliminado.";
} else {
    echo "Usuario no encontrado.";
}

// Ventajas:
// ✅ Método intuitivo y expresivo
// ✅ Verificación automática de existencia
// ✅ El objeto se limpia automáticamente
// ✅ Protección contra eliminaciones accidentales
```

### 🗑️ ¿Qué hace `trash()` automáticamente?
- 🛡️ **Verificación**: Confirma que el registro existe
- 💫 **Limpieza**: Vacía el objeto después de eliminar
- ⚡ **Eficiencia**: Usa la clave primaria para eliminación rápida
- 📝 **Logging**: Registra la operación para auditoría

---

## Exportar a Array

A menudo, necesitarás convertir los datos de un modelo a un array, por ejemplo, para generar una respuesta JSON en una API. Puedes usar el método `export()`.

```php
$user = VersaModel::load('users', 1);
$userData = $user->export();

// $userData es ahora un array asociativo:
// [
//   'id' => 1,
//   'name' => 'Juan Carlos Pérez',
//   'email' => 'juan.perez@example.com',
//   'status' => 'inactive',
//   'created_at' => '2024-07-29 10:00:00'
// ]

header('Content-Type: application/json');
echo json_encode($userData);
```

Para exportar un array de modelos, puedes usar el método estático `exportAll()`.

```php
$users = VersaModel::findAll('users');
$usersData = VersaModel::exportAll($users);

echo json_encode($usersData);
```

## Siguientes Pasos

Ahora que dominas las operaciones básicas, tienes varias opciones para continuar:

- **[Query Builder](02-query-builder.md)** - Construye consultas más complejas con sintaxis fluida
- **[Modelos y Objetos](03-models-and-objects.md)** - Crea modelos personalizados con lógica de negocio
- **[Validación y Mass Assignment](05-validation-mass-assignment.md)** - Protege tu aplicación con validación automática

> **💡 Tip de Seguridad:** Para aplicaciones en producción, siempre considera usar **modelos personalizados con validación** en lugar de VersaModel genérico. Esto te protege contra vulnerabilidades de seguridad y mantiene la integridad de tus datos.

```
